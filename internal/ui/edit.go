package ui

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"proxyscope/internal/model"
)

// This file converts between the model types and the structured edit forms
// used by the Intercept and Repeater views (method, URL, "Name: value" header
// lines, body text) and validates what comes back.

// headersText renders headers as editable "Name: value" lines: Host first,
// the rest sorted by name (map order is random, the UI must be stable).
func headersText(h http.Header) string {
	var b strings.Builder
	names := make([]string, 0, len(h))
	for name := range h {
		if name != "Host" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	if hosts := h.Values("Host"); len(hosts) > 0 {
		names = append([]string{"Host"}, names...)
	}
	for _, name := range names {
		for _, v := range h.Values(name) {
			b.WriteString(name + ": " + v + "\n")
		}
	}
	return b.String()
}

// parseHeadersText is the inverse of headersText. Blank lines are ignored;
// every other line must be "Name: value" with a valid header name.
func parseHeadersText(s string) (http.Header, error) {
	h := http.Header{}
	for i, line := range strings.Split(s, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		name = strings.TrimSpace(name)
		if !ok || !isToken(name) {
			return nil, fmt.Errorf("header line %d is not \"Name: value\": %q", i+1, truncate(line, 60))
		}
		if strings.ContainsAny(value, "\x00\r\n") {
			return nil, fmt.Errorf("header line %d: invalid characters in value", i+1)
		}
		h.Add(name, strings.TrimSpace(value))
	}
	return h, nil
}

// isToken reports whether s is a valid HTTP token (method or header name).
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
		if !ok {
			return false
		}
	}
	return true
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// editableBody renders a body for an edit form.
func editableBody(h http.Header, body []byte) bodyView {
	v := renderBody(h, body, int64(len(body)))
	_, _, v.Editable = editableText(h, body)
	return v
}

// editableText returns the body as editable text (decompressed if needed) when
// that is lossless: complete valid UTF-8 without NUL bytes, within the display
// limit and not cut short by the decompression cap.
func editableText(h http.Header, body []byte) (text, decodedFrom string, ok bool) {
	data, from := decodeForDisplay(h, body)
	if len(data) >= maxDecoded || len(data) > maxTextView {
		return "", "", false
	}
	if from != "" && len(body) > 0 && len(data) == 0 {
		return "", "", false
	}
	t, isText := asText(data, false)
	if !isText {
		return "", "", false
	}
	return t, from, true
}

// applyBodyEdit returns the body to send given the edited text. If the text is
// unchanged the original bytes are kept exactly (compression, line endings and
// all). If it changed, the new text is used as-is and, when the original was
// compressed, the now-wrong Content-Encoding is removed from newHeaders.
// A nil text means "leave the body alone" (binary bodies are not editable).
func applyBodyEdit(newHeaders, origHeaders http.Header, orig []byte, text *string) []byte {
	if text == nil {
		return orig
	}
	decoded, from := decodeForDisplay(origHeaders, orig)
	origText := string(decoded)
	nt := normalizeNL(*text)
	if nt == normalizeNL(origText) {
		return orig
	}
	// Browsers hand back textareas with LF line endings; if the original body
	// used CRLF throughout (multipart, form posts, ...), keep it that way.
	if strings.Contains(origText, "\r\n") && !hasBareLF(origText) {
		nt = strings.ReplaceAll(nt, "\n", "\r\n")
	}
	if from != "" && strings.EqualFold(strings.TrimSpace(newHeaders.Get("Content-Encoding")), from) {
		newHeaders.Del("Content-Encoding")
	}
	return []byte(nt)
}

func normalizeNL(s string) string { return strings.ReplaceAll(s, "\r\n", "\n") }

func hasBareLF(s string) bool {
	return strings.Contains(strings.ReplaceAll(s, "\r\n", ""), "\n")
}

// requestEdit is the edit form of a request as sent by the browser.
type requestEdit struct {
	Method  string  `json:"method"`
	URL     string  `json:"url"`
	Headers string  `json:"headers"`
	Body    *string `json:"body"` // nil = body not editable/unchanged
}

// responseEdit is the edit form of a response as sent by the browser.
type responseEdit struct {
	Status  int     `json:"status"`
	Headers string  `json:"headers"`
	Body    *string `json:"body"`
}

// buildRequest validates an edit form and produces the request to send. orig
// supplies the original body and headers for unchanged/compressed bodies (it
// may be an empty request when composing from scratch).
func buildRequest(orig *model.Request, e *requestEdit) (*model.Request, error) {
	method := strings.TrimSpace(e.Method)
	if !isToken(method) {
		return nil, fmt.Errorf("invalid HTTP method %q", truncate(method, 30))
	}
	u, err := url.Parse(strings.TrimSpace(e.URL))
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %v", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("URL must start with http:// or https://")
	}
	if u.Hostname() == "" {
		return nil, fmt.Errorf("URL has no host")
	}
	hdr, err := parseHeadersText(e.Headers)
	if err != nil {
		return nil, err
	}
	return &model.Request{
		Method: method,
		URL:    u.String(),
		Header: hdr,
		Body:   applyBodyEdit(hdr, orig.Header, orig.Body, e.Body),
	}, nil
}

// buildResponse validates an edit form and produces the response to deliver.
func buildResponse(orig *model.Response, e *responseEdit) (*model.Response, error) {
	if e.Status < 200 || e.Status > 599 {
		return nil, fmt.Errorf("status code must be between 200 and 599")
	}
	hdr, err := parseHeadersText(e.Headers)
	if err != nil {
		return nil, err
	}
	return &model.Response{
		StatusCode: e.Status,
		Header:     hdr,
		Body:       applyBodyEdit(hdr, orig.Header, orig.Body, e.Body),
	}, nil
}

// --- views ---

type requestEditView struct {
	Method  string   `json:"method"`
	URL     string   `json:"url"`
	Headers string   `json:"headers"`
	Body    bodyView `json:"body"`
}

type responseEditView struct {
	Status  int      `json:"status"`
	Headers string   `json:"headers"`
	Body    bodyView `json:"body"`
}

func newRequestEditView(r *model.Request) requestEditView {
	return requestEditView{Method: r.Method, URL: r.URL, Headers: headersText(r.Header), Body: editableBody(r.Header, r.Body)}
}

func newResponseEditView(r *model.Response) *responseEditView {
	if r == nil {
		return nil
	}
	return &responseEditView{Status: r.StatusCode, Headers: headersText(r.Header), Body: editableBody(r.Header, r.Body)}
}

// exchangeRequest reconstructs the request of a stored exchange, with Host
// made explicit (it is stored separately from the other headers).
func exchangeRequest(ex *model.Exchange) *model.Request {
	h := ex.ReqHeaders.Clone()
	if h == nil {
		h = http.Header{}
	}
	h.Set("Host", ex.Host)
	return &model.Request{Method: ex.Method, URL: ex.URL, Header: h, Body: bytes.Clone(ex.ReqBody)}
}
