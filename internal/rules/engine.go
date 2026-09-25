package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"gopkg.in/yaml.v3"

	"proxyscope/internal/model"
)

// Engine holds the active, compiled rule set and applies it at the two
// proxy.forward pause points. It is safe for concurrent use: Apply* only
// ever reads an atomically-published *compiledSet, so a reload never blocks
// or is seen half-done by a request in flight (same spirit as
// intercept.Manager's "never hold a lock while blocking" rule, adapted here
// to "never let a reader see a partially-built rule set").
type Engine struct {
	path string

	active atomic.Pointer[compiledSet]

	writeMu sync.Mutex // serializes Load/SaveRules/SaveRaw against each other
}

// New creates an Engine bound to path. It starts with zero rules; call Load
// to read the file (or Save to create one from scratch, e.g. from the UI).
func New(path string) *Engine {
	e := &Engine{path: path}
	e.active.Store(&compiledSet{})
	return e
}

// Path returns the rules file this Engine loads from and saves to.
func (e *Engine) Path() string { return e.path }

// Load (re-)reads the rules file from disk, validates and compiles it, and
// atomically makes it the active set. A missing file is not an error: the
// Engine simply keeps running with zero rules (a fresh install has none yet).
// Any other error (unreadable file, malformed YAML, a rule that fails
// validation) is returned and the previously active rule set, if any, is
// left running unchanged — a bad reload never blanks out working rules.
func (e *Engine) Load() error {
	e.writeMu.Lock()
	defer e.writeMu.Unlock()
	data, err := os.ReadFile(e.path)
	if os.IsNotExist(err) {
		e.active.Store(&compiledSet{})
		return nil
	}
	if err != nil {
		return fmt.Errorf("read rules file %s: %w", e.path, err)
	}
	return e.loadBytes(data)
}

// loadBytes parses, validates, compiles and activates data. Caller holds writeMu.
func (e *Engine) loadBytes(data []byte) error {
	var f File
	if err := yaml.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("parse rules file %s: %w", e.path, err)
	}
	set, err := compile(f)
	if err != nil {
		return fmt.Errorf("rules file %s: %w", e.path, err)
	}
	e.active.Store(set)
	return nil
}

// Rules returns the currently active rules, in file order, as they would be
// re-serialized (defaults such as scope.path_match filled in).
func (e *Engine) Rules() []Rule {
	set := e.active.Load()
	out := make([]Rule, len(set.rules))
	for i, c := range set.rules {
		out[i] = c.rule
	}
	return out
}

// ReadRaw returns the rules file's current text, or a canonical empty file
// if it does not exist yet (so the UI's raw-YAML editor always has something
// sensible to start from).
func (e *Engine) ReadRaw() (string, error) {
	data, err := os.ReadFile(e.path)
	if os.IsNotExist(err) {
		empty, err := yaml.Marshal(File{Version: 1, Rules: []Rule{}})
		if err != nil {
			return "", err
		}
		return string(empty), nil
	}
	if err != nil {
		return "", fmt.Errorf("read rules file %s: %w", e.path, err)
	}
	return string(data), nil
}

// SaveRules validates and compiles rules, then, only if that succeeds,
// writes them to the rules file (replacing its contents; this loses any
// hand-added comments, which is why the raw-YAML editor exists for that
// case) and activates them. On a validation error nothing is written or
// activated: the previous rule set keeps running.
func (e *Engine) SaveRules(rules []Rule) error {
	f := File{Version: 1, Rules: rules}
	data, err := yaml.Marshal(f)
	if err != nil {
		return fmt.Errorf("encode rules: %w", err)
	}
	return e.saveValidated(f, data)
}

// SaveRaw validates and compiles the YAML text a user hand-edited (or
// pasted) in the UI's raw editor, then, only if that succeeds, writes it to
// the rules file verbatim (preserving comments/formatting) and activates it.
func (e *Engine) SaveRaw(text string) error {
	var f File
	if err := yaml.Unmarshal([]byte(text), &f); err != nil {
		return fmt.Errorf("parse rules: %w", err)
	}
	return e.saveValidated(f, []byte(text))
}

func (e *Engine) saveValidated(f File, data []byte) error {
	set, err := compile(f)
	if err != nil {
		return err
	}
	e.writeMu.Lock()
	defer e.writeMu.Unlock()
	if err := os.MkdirAll(filepath.Dir(e.path), 0o755); err != nil {
		return fmt.Errorf("create rules directory: %w", err)
	}
	if err := writeFileAtomic(e.path, data); err != nil {
		return fmt.Errorf("write rules file %s: %w", e.path, err)
	}
	e.active.Store(set)
	return nil
}

// writeFileAtomic writes data to path via a temp file + rename, so a save
// that fails partway (disk full, crash) never leaves a truncated/corrupt
// rules file behind for the next Load to choke on.
func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".rules-*.yaml.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) // no-op once the rename below succeeds
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

// NeedsRequestBody reports whether any enabled request-direction rule
// inspects or replaces the body, so proxy.forward knows whether it is worth
// buffering the request body at all when live intercept is off.
func (e *Engine) NeedsRequestBody() bool { return e.active.Load().needsReqBody }

// NeedsResponseBody is NeedsRequestBody for the response direction.
func (e *Engine) NeedsResponseBody() bool { return e.active.Load().needsRespBody }

// ApplyRequest runs every enabled request-direction rule against req, in
// file order, applying each match's action before the next rule is
// evaluated (so later rules see earlier ones' edits). It mutates req in
// place and returns the ids of the rules that fired, in firing order.
// bodyAvailable must be true only when req.Body actually holds the full,
// buffered request body; a rule whose condition or action touches the body
// never fires when it is false, however its scope/other conditions look.
func (e *Engine) ApplyRequest(req *model.Request, bodyAvailable bool) []string {
	set := e.active.Load()
	if len(set.rules) == 0 {
		return nil
	}
	host, path, method := scopeOf(req.URL, req.Method)
	t := target{host: host, path: path, method: method, header: req.Header, body: req.Body, bodyAvailable: bodyAvailable}
	var fired []string
	for _, c := range set.rules {
		if !c.matches(DirectionRequest, t) {
			continue
		}
		req.Body, _ = c.action.apply(req.Header, req.Body, 0)
		t.body = req.Body
		fired = append(fired, c.rule.ID)
	}
	return fired
}

// ApplyResponse is ApplyRequest for the response direction. req is the
// request that produced resp: its host/path/method decide scope, but the
// action (and any header/body/status conditions) look at resp. bodyAvailable
// is resp.Body's counterpart to ApplyRequest's.
func (e *Engine) ApplyResponse(req *model.Request, resp *model.Response, bodyAvailable bool) []string {
	set := e.active.Load()
	if len(set.rules) == 0 {
		return nil
	}
	host, path, method := scopeOf(req.URL, req.Method)
	t := target{host: host, path: path, method: method, header: resp.Header, body: resp.Body, status: resp.StatusCode, bodyAvailable: bodyAvailable}
	var fired []string
	for _, c := range set.rules {
		if !c.matches(DirectionResponse, t) {
			continue
		}
		resp.Body, resp.StatusCode = c.action.apply(resp.Header, resp.Body, resp.StatusCode)
		t.body, t.status = resp.Body, resp.StatusCode
		fired = append(fired, c.rule.ID)
	}
	return fired
}
