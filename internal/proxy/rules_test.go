package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"proxyscope/internal/model"
	"proxyscope/internal/rules"
)

// fakeInterceptor is a synchronous, in-test-goroutine stand-in for
// intercept.Manager: it never actually blocks, but records what it was
// handed so a test can assert what the rule engine had already changed by
// the time intercept would see it.
type fakeInterceptor struct {
	reqOn, respOn bool
	sawReq        *model.Request
	sawResp       *model.Response
}

func (f *fakeInterceptor) RequestEnabled() bool  { return f.reqOn }
func (f *fakeInterceptor) ResponseEnabled() bool { return f.respOn }
func (f *fakeInterceptor) HoldRequest(_ context.Context, req *model.Request) model.Outcome {
	c := req.Clone()
	f.sawReq = c
	return model.Outcome{}
}
func (f *fakeInterceptor) HoldResponse(_ context.Context, _ *model.Request, resp *model.Response) model.Outcome {
	c := resp.Clone()
	f.sawResp = c
	return model.Outcome{}
}

func newRulesEngine(t *testing.T, yamlText string) *rules.Engine {
	t.Helper()
	e := rules.New(filepath.Join(t.TempDir(), "rules.yaml"))
	if err := e.SaveRaw(yamlText); err != nil {
		t.Fatalf("SaveRaw: %v", err)
	}
	return e
}

func TestRuleFiresWithoutInterceptOn(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		io.WriteString(w, `{"valid": false}`)
	}))
	defer up.Close()

	re := newRulesEngine(t, `version: 1
rules:
  - id: verify-bypass
    enabled: true
    direction: response
    conditions:
      - {type: body, match: regex, value: '"valid"\s*:\s*false'}
    action: {type: replace_body, body: '{"valid": true}'}
`)
	u, sink, _ := startProxyRules(t, testCfg(1<<20, 2*time.Second, false), nil, re)
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(u)}, Timeout: 5 * time.Second}

	resp, err := c.Get(up.URL + "/verify")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != `{"valid": true}` {
		t.Fatalf("client received %q, want the rule-replaced body", b)
	}

	ex := sink.last(t)
	if !ex.RuleFired() || ex.RulesApplied[0] != "verify-bypass" {
		t.Fatalf("exchange RulesApplied = %v", ex.RulesApplied)
	}
	if string(ex.RespBody) != `{"valid": true}` {
		t.Fatalf("stored body = %q, want the rule-replaced body (history must show what was actually delivered)", ex.RespBody)
	}
}

func TestRulesRunBeforeInterceptHold(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		io.WriteString(w, `{"valid": false}`)
	}))
	defer up.Close()

	re := newRulesEngine(t, `version: 1
rules:
  - id: verify-bypass
    enabled: true
    direction: response
    action: {type: replace_body, body: '{"valid": true}'}
`)
	icpt := &fakeInterceptor{respOn: true}
	u, _, _ := startProxyRules(t, testCfg(1<<20, 2*time.Second, false), icpt, re)
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(u)}, Timeout: 5 * time.Second}

	if _, err := c.Get(up.URL + "/verify"); err != nil {
		t.Fatal(err)
	}
	if icpt.sawResp == nil {
		t.Fatal("intercept never saw the response")
	}
	if string(icpt.sawResp.Body) != `{"valid": true}` {
		t.Fatalf("intercept saw body %q, want the already rule-transformed body (rules must run before the hold)", icpt.sawResp.Body)
	}
}

func TestRuleSkipNoteWhenBodyTooLarge(t *testing.T) {
	big := strings.Repeat("x", 100)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		io.WriteString(w, big)
	}))
	defer up.Close()

	re := newRulesEngine(t, `version: 1
rules:
  - id: r
    enabled: true
    direction: response
    action: {type: replace_body, body: "short"}
`)
	u, sink, _ := startProxyRules(t, testCfg(10, 2*time.Second, false), nil, re) // max-body smaller than the response
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(u)}, Timeout: 5 * time.Second}

	resp, err := c.Get(up.URL + "/big")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != big {
		t.Fatalf("oversized body must still be forwarded in full untouched, got %d bytes", len(b))
	}

	ex := sink.last(t)
	if ex.RuleFired() {
		t.Fatalf("a rule that cannot see the body must not fire: %v", ex.RulesApplied)
	}
	if !strings.Contains(ex.Note, "rule-processed") || !strings.Contains(ex.Note, "-max-body") {
		t.Fatalf("note = %q, want it to explain the body was too large for rules", ex.Note)
	}
}

func TestHeaderOnlyRuleDoesNotBufferLargeBody(t *testing.T) {
	big := strings.Repeat("y", 1000)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		io.WriteString(w, big)
	}))
	defer up.Close()

	// max-body is smaller than the response, but the only rule is header-only
	// (add_header), so it should never need to buffer the body at all: the
	// large response must stream through untouched, with no skip note.
	re := newRulesEngine(t, `version: 1
rules:
  - id: header-only
    enabled: true
    direction: response
    action: {type: add_header, name: X-Rule-Hit, value: "1"}
`)
	u, sink, _ := startProxyRules(t, testCfg(10, 2*time.Second, false), nil, re)
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(u)}, Timeout: 5 * time.Second}

	resp, err := c.Get(up.URL + "/big")
	if err != nil {
		t.Fatal(err)
	}
	if resp.Header.Get("X-Rule-Hit") != "1" {
		t.Fatal("header-only rule did not fire")
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(b) != big {
		t.Fatalf("body must stream through in full, got %d bytes", len(b))
	}

	ex := sink.last(t)
	if !ex.RuleFired() {
		t.Fatal("header rule should have been recorded as fired")
	}
	if strings.Contains(ex.Note, "rule-processed") {
		t.Fatalf("a header-only rule must not force body buffering, note = %q", ex.Note)
	}
}

func TestRequestBodyRuleFiresWithoutIntercept(t *testing.T) {
	var gotBody string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(200)
	}))
	defer up.Close()

	re := newRulesEngine(t, `version: 1
rules:
  - id: patch-body
    enabled: true
    direction: request
    action: {type: body_regex_replace, pattern: "false", replacement: "true"}
`)
	u, sink, _ := startProxyRules(t, testCfg(1<<20, 2*time.Second, false), nil, re)
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(u)}, Timeout: 5 * time.Second}

	resp, err := c.Post(up.URL+"/x", "text/plain", strings.NewReader("valid=false"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if gotBody != "valid=true" {
		t.Fatalf("upstream received %q, want the rule-patched body", gotBody)
	}
	ex := sink.last(t)
	if !ex.RuleFired() || ex.RulesApplied[0] != "patch-body" {
		t.Fatalf("RulesApplied = %v", ex.RulesApplied)
	}
	if string(ex.ReqBody) != "valid=true" {
		t.Fatalf("stored request body = %q, want the rule-patched body", ex.ReqBody)
	}
}

func TestRequestRuleRemovesHeaderIndependentOfIntercept(t *testing.T) {
	var gotHeader string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-App-Integrity")
		w.WriteHeader(200)
	}))
	defer up.Close()

	re := newRulesEngine(t, `version: 1
rules:
  - id: strip-integrity
    enabled: true
    direction: request
    action: {type: remove_header, name: X-App-Integrity}
`)
	u, sink, _ := startProxyRules(t, testCfg(1<<20, 2*time.Second, false), nil, re)
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(u)}, Timeout: 5 * time.Second}

	req, _ := http.NewRequest("GET", up.URL+"/activate", nil)
	req.Header.Set("X-App-Integrity", "abc")
	if _, err := c.Do(req); err != nil {
		t.Fatal(err)
	}
	if gotHeader != "" {
		t.Fatalf("upstream still received X-App-Integrity=%q", gotHeader)
	}
	ex := sink.last(t)
	if !ex.RuleFired() || ex.RulesApplied[0] != "strip-integrity" {
		t.Fatalf("RulesApplied = %v", ex.RulesApplied)
	}
	if ex.ReqHeaders.Get("X-App-Integrity") != "" {
		t.Fatalf("stored request headers still show the removed header: %v", ex.ReqHeaders)
	}
}
