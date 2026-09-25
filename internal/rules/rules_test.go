package rules

import (
	"path/filepath"
	"strings"
	"testing"

	"proxyscope/internal/model"
)

func mustEngine(t *testing.T, yamlText string) *Engine {
	t.Helper()
	e := New(filepath.Join(t.TempDir(), "rules.yaml"))
	if yamlText == "" {
		return e
	}
	if err := e.SaveRaw(yamlText); err != nil {
		t.Fatalf("SaveRaw: %v", err)
	}
	return e
}

func TestLoadMissingFileIsEmpty(t *testing.T) {
	e := New(filepath.Join(t.TempDir(), "nope.yaml"))
	if err := e.Load(); err != nil {
		t.Fatalf("Load of missing file: %v", err)
	}
	if got := e.ApplyRequest(&model.Request{Method: "GET", URL: "http://example.com/", Header: map[string][]string{}}, true); got != nil {
		t.Fatalf("expected no rules fired, got %v", got)
	}
}

func TestValidationErrors(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{"missing id", `version: 1
rules:
  - enabled: true
    direction: request
    action: {type: remove_header, name: X}
`, "id is required"},
		{"bad id chars", `version: 1
rules:
  - id: "bad id!"
    enabled: true
    direction: request
    action: {type: remove_header, name: X}
`, "must contain only letters"},
		{"duplicate id", `version: 1
rules:
  - id: a
    enabled: true
    direction: request
    action: {type: remove_header, name: X}
  - id: a
    enabled: true
    direction: request
    action: {type: remove_header, name: Y}
`, "duplicate rule id"},
		{"bad direction", `version: 1
rules:
  - id: a
    enabled: true
    direction: sideways
    action: {type: remove_header, name: X}
`, "direction must be"},
		{"bad regex", `version: 1
rules:
  - id: a
    enabled: true
    direction: response
    conditions:
      - {type: body, match: regex, value: "("}
    action: {type: replace_body, body: "x"}
`, "invalid regex"},
		{"status condition on request rule", `version: 1
rules:
  - id: a
    enabled: true
    direction: request
    conditions:
      - {type: status, equals: 200}
    action: {type: remove_header, name: X}
`, "status condition only applies to response"},
		{"set_status on request rule", `version: 1
rules:
  - id: a
    enabled: true
    direction: request
    action: {type: set_status, status: 200}
`, "set_status only applies to response"},
		{"impossible status conditions", `version: 1
rules:
  - id: a
    enabled: true
    direction: response
    conditions:
      - {type: status, equals: 200}
      - {type: status, equals: 404}
    action: {type: replace_body, body: "x"}
`, "impossible"},
		{"impossible header conditions", `version: 1
rules:
  - id: a
    enabled: true
    direction: request
    conditions:
      - {type: header, name: X, match: exact, value: "1"}
      - {type: header, name: X, match: exact, value: "2"}
    action: {type: remove_header, name: X}
`, "can never equal both"},
		{"capture group out of range", `version: 1
rules:
  - id: a
    enabled: true
    direction: response
    action: {type: body_regex_replace, pattern: "abc", replacement: "$1"}
`, "only has 0 group"},
		{"named capture group missing", `version: 1
rules:
  - id: a
    enabled: true
    direction: response
    action: {type: body_regex_replace, pattern: "(?P<foo>abc)", replacement: "${bar}"}
`, "does not define"},
		{"bad version", `version: 2
rules: []
`, "unsupported rules file version"},
		{"unknown action type", `version: 1
rules:
  - id: a
    enabled: true
    direction: request
    action: {type: nonsense}
`, "type must be one of"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := New(filepath.Join(t.TempDir(), "rules.yaml"))
			err := e.SaveRaw(tc.yaml)
			if err == nil {
				t.Fatalf("expected an error containing %q, got nil", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want substring %q", err.Error(), tc.want)
			}
		})
	}
}

func TestValidCaptureGroupsAccepted(t *testing.T) {
	yamlText := `version: 1
rules:
  - id: a
    enabled: true
    direction: response
    action: {type: body_regex_replace, pattern: "(?P<foo>abc)(def)", replacement: "$2-${foo}-$0"}
`
	if _, err := New(filepath.Join(t.TempDir(), "r.yaml")).ReadRaw(); err != nil {
		t.Fatalf("ReadRaw on missing file: %v", err)
	}
	e := mustEngine(t, yamlText)
	if len(e.Rules()) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(e.Rules()))
	}
}

func TestRequestRuleFiresIndependentlyOfIntercept(t *testing.T) {
	e := mustEngine(t, `version: 1
rules:
  - id: strip-integrity
    enabled: true
    direction: request
    scope: {host: "license.example.com", path: /api/activate, method: POST}
    action: {type: remove_header, name: X-App-Integrity}
`)
	req := &model.Request{
		Method: "POST",
		URL:    "https://license.example.com/api/activate",
		Header: map[string][]string{"X-App-Integrity": {"abc"}, "Content-Type": {"application/json"}},
	}
	fired := e.ApplyRequest(req, true)
	if len(fired) != 1 || fired[0] != "strip-integrity" {
		t.Fatalf("fired = %v, want [strip-integrity]", fired)
	}
	if req.Header.Get("X-App-Integrity") != "" {
		t.Fatalf("header not removed: %v", req.Header)
	}
	if req.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("unrelated header touched: %v", req.Header)
	}
}

func TestResponseRuleReplacesBodyOnMatch(t *testing.T) {
	e := mustEngine(t, `version: 1
rules:
  - id: verify-bypass
    enabled: true
    direction: response
    scope: {host: license.example.com, path: /api/verify}
    conditions:
      - {type: status, equals: 200}
      - {type: body, match: regex, value: '"valid"\s*:\s*false'}
    action: {type: replace_body, body: '{"valid": true, "reason": "ok"}'}
`)
	req := &model.Request{Method: "GET", URL: "https://license.example.com/api/verify", Header: map[string][]string{}}
	resp := &model.Response{StatusCode: 200, Header: map[string][]string{}, Body: []byte(`{"valid": false}`)}
	fired := e.ApplyResponse(req, resp, true)
	if len(fired) != 1 || fired[0] != "verify-bypass" {
		t.Fatalf("fired = %v", fired)
	}
	if string(resp.Body) != `{"valid": true, "reason": "ok"}` {
		t.Fatalf("body = %q", resp.Body)
	}

	// A response that doesn't match the body condition is untouched.
	resp2 := &model.Response{StatusCode: 200, Header: map[string][]string{}, Body: []byte(`{"valid": true}`)}
	if fired := e.ApplyResponse(req, resp2, true); fired != nil {
		t.Fatalf("expected no match, got %v", fired)
	}
	if string(resp2.Body) != `{"valid": true}` {
		t.Fatalf("body should be unchanged, got %q", resp2.Body)
	}
}

func TestMultipleRulesSeePriorTransformation(t *testing.T) {
	e := mustEngine(t, `version: 1
rules:
  - id: first
    enabled: true
    direction: response
    action: {type: body_regex_replace, pattern: "false", replacement: "true"}
  - id: second
    enabled: true
    direction: response
    conditions:
      - {type: body, match: contains, value: "true"}
    action: {type: add_header, name: X-Patched, value: "1"}
`)
	req := &model.Request{Method: "GET", URL: "http://x/", Header: map[string][]string{}}
	resp := &model.Response{StatusCode: 200, Header: map[string][]string{}, Body: []byte("false")}
	fired := e.ApplyResponse(req, resp, true)
	if len(fired) != 2 {
		t.Fatalf("expected both rules to fire (second depends on first's edit), got %v", fired)
	}
	if resp.Header.Get("X-Patched") != "1" {
		t.Fatalf("second rule's action did not run")
	}
}

func TestBodyRuleNeverFiresWithoutBody(t *testing.T) {
	e := mustEngine(t, `version: 1
rules:
  - id: body-rule
    enabled: true
    direction: response
    action: {type: replace_body, body: "short"}
  - id: header-rule
    enabled: true
    direction: response
    action: {type: add_header, name: X-Hit, value: "1"}
`)
	req := &model.Request{Method: "GET", URL: "http://x/", Header: map[string][]string{}}
	resp := &model.Response{StatusCode: 200, Header: map[string][]string{}, Body: nil}
	fired := e.ApplyResponse(req, resp, false) // body was never buffered (too large/streaming)
	if len(fired) != 1 || fired[0] != "header-rule" {
		t.Fatalf("fired = %v, want only the header rule; a body-touching rule must never fire when the body was not captured", fired)
	}
	if resp.Header.Get("X-Hit") != "1" {
		t.Fatal("header-only rule should still have fired")
	}

	bodyCond := mustEngine(t, `version: 1
rules:
  - id: body-cond
    enabled: true
    direction: response
    conditions:
      - {type: body, match: contains, value: "x"}
    action: {type: add_header, name: X-Hit, value: "1"}
`)
	resp2 := &model.Response{StatusCode: 200, Header: map[string][]string{}}
	if fired := bodyCond.ApplyResponse(req, resp2, false); fired != nil {
		t.Fatalf("a rule with a body condition must not fire without the body, got %v", fired)
	}
}

func TestDisabledRuleNeverFires(t *testing.T) {
	e := mustEngine(t, `version: 1
rules:
  - id: off
    enabled: false
    direction: request
    action: {type: add_header, name: X, value: "1"}
`)
	req := &model.Request{Method: "GET", URL: "http://x/", Header: map[string][]string{}}
	if fired := e.ApplyRequest(req, true); fired != nil {
		t.Fatalf("disabled rule fired: %v", fired)
	}
	if e.NeedsRequestBody() {
		t.Fatalf("a disabled rule should not force body buffering")
	}
}

func TestWildcardHostAndPathPrefix(t *testing.T) {
	e := mustEngine(t, `version: 1
rules:
  - id: r
    enabled: true
    direction: request
    scope: {host: "*.example.com", path: /api/, path_match: prefix}
    action: {type: add_header, name: X-Hit, value: "1"}
`)
	for _, u := range []string{"http://sub.example.com/api/anything", "http://example.com/api/x"} {
		req := &model.Request{Method: "GET", URL: u, Header: map[string][]string{}}
		if fired := e.ApplyRequest(req, true); len(fired) != 1 {
			t.Errorf("url %s: expected a match, got %v", u, fired)
		}
	}
	req := &model.Request{Method: "GET", URL: "http://other.com/api/x", Header: map[string][]string{}}
	if fired := e.ApplyRequest(req, true); fired != nil {
		t.Fatalf("host should not have matched: %v", fired)
	}
}

func TestNeedsBodyReflectsOnlyBodyTouchingRules(t *testing.T) {
	e := mustEngine(t, `version: 1
rules:
  - id: header-only
    enabled: true
    direction: request
    action: {type: add_header, name: X, value: "1"}
`)
	if e.NeedsRequestBody() {
		t.Fatalf("a header-only rule should not require buffering the body")
	}
	e2 := mustEngine(t, `version: 1
rules:
  - id: body-rule
    enabled: true
    direction: request
    action: {type: replace_body, body: "x"}
`)
	if !e2.NeedsRequestBody() {
		t.Fatalf("a body-replacing rule should require buffering the body")
	}
}

func TestBadReloadKeepsPreviousRulesActive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.yaml")
	e := New(path)
	if err := e.SaveRaw(`version: 1
rules:
  - id: good
    enabled: true
    direction: request
    action: {type: add_header, name: X, value: "1"}
`); err != nil {
		t.Fatalf("initial save: %v", err)
	}
	// Simulate a hand-edit that breaks the file, then reload.
	if err := e.SaveRaw("not: valid: yaml: ["); err == nil {
		t.Fatalf("expected SaveRaw to reject invalid YAML")
	}
	req := &model.Request{Method: "GET", URL: "http://x/", Header: map[string][]string{}}
	if fired := e.ApplyRequest(req, true); len(fired) != 1 || fired[0] != "good" {
		t.Fatalf("previous rule set should still be active after a failed save, got %v", fired)
	}
}

func TestSaveRulesRoundTripsThroughFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.yaml")
	e := New(path)
	rules := []Rule{{
		ID: "r1", Enabled: true, Direction: DirectionRequest,
		Action: Action{Type: ActionAddHeader, Name: "X", Value: "1"},
	}}
	if err := e.SaveRules(rules); err != nil {
		t.Fatalf("SaveRules: %v", err)
	}
	// A fresh Engine reading the same path should see the same rule.
	e2 := New(path)
	if err := e2.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	got := e2.Rules()
	if len(got) != 1 || got[0].ID != "r1" {
		t.Fatalf("got %+v", got)
	}
}
