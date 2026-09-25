package ui

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"proxyscope/internal/intercept"
	"proxyscope/internal/model"
)

func TestHeadersTextRoundTripAndValidation(t *testing.T) {
	h := http.Header{"Host": {"example.com"}, "X-B": {"2"}, "X-A": {"1", "1b"}}
	text := headersText(h)
	if !strings.HasPrefix(text, "Host: example.com\n") || !strings.Contains(text, "X-A: 1\nX-A: 1b\nX-B: 2") {
		t.Fatalf("text = %q", text)
	}
	back, err := parseHeadersText(text)
	if err != nil || back.Get("X-B") != "2" || len(back.Values("X-A")) != 2 {
		t.Fatalf("round trip: %v %v", back, err)
	}
	for _, bad := range []string{"no colon here", ": empty name", "bad name: x", "X: a\x00b"} {
		if _, err := parseHeadersText(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
	if h, err := parseHeadersText("\n\r\nA: 1\r\n\n"); err != nil || h.Get("A") != "1" {
		t.Fatalf("blank lines/CRLF: %v %v", h, err)
	}
}

func gz(s string) []byte {
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	w.Write([]byte(s))
	w.Close()
	return b.Bytes()
}

func ptr(s string) *string { return &s }

func TestApplyBodyEdit(t *testing.T) {
	// Unchanged text keeps the exact original bytes (compressed stays compressed).
	orig := gz("hello")
	hdr := http.Header{"Content-Encoding": {"gzip"}}
	if got := applyBodyEdit(hdr.Clone(), hdr, orig, ptr("hello")); !bytes.Equal(got, orig) {
		t.Fatal("unchanged gzip body must be forwarded byte-for-byte")
	}
	// Changed text replaces the body and drops the now-wrong Content-Encoding.
	nh := hdr.Clone()
	if got := applyBodyEdit(nh, hdr, orig, ptr("bye")); string(got) != "bye" || nh.Get("Content-Encoding") != "" {
		t.Fatalf("edited gzip body: %q %v", got, nh)
	}
	// nil = untouched (binary bodies).
	if got := applyBodyEdit(http.Header{}, http.Header{}, []byte{0, 1}, nil); !bytes.Equal(got, []byte{0, 1}) {
		t.Fatal("nil edit must keep the body")
	}
	// A textarea returns LF; a CRLF body must stay unchanged if untouched, and stay CRLF if edited.
	crlf := []byte("a=1\r\nb=2\r\n")
	if got := applyBodyEdit(http.Header{}, http.Header{}, crlf, ptr("a=1\nb=2\n")); !bytes.Equal(got, crlf) {
		t.Fatalf("untouched CRLF body changed: %q", got)
	}
	if got := applyBodyEdit(http.Header{}, http.Header{}, crlf, ptr("a=1\nb=3\n")); string(got) != "a=1\r\nb=3\r\n" {
		t.Fatalf("edited CRLF body lost its line endings: %q", got)
	}
}

func TestEditableBody(t *testing.T) {
	if v := editableBody(http.Header{}, []byte("text")); !v.Editable || v.Content != "text" {
		t.Fatalf("text: %+v", v)
	}
	if v := editableBody(http.Header{}, nil); !v.Editable {
		t.Fatal("empty body is editable (you can add one)")
	}
	if v := editableBody(http.Header{}, []byte{0xff, 0x00, 0x01}); v.Editable || v.Encoding != "hex" {
		t.Fatalf("binary: %+v", v)
	}
	if v := editableBody(http.Header{"Content-Encoding": {"gzip"}}, gz("zipped")); !v.Editable || v.Content != "zipped" || v.DecodedFrom != "gzip" {
		t.Fatalf("gzip: %+v", v)
	}
}

func TestBuildRequestAndResponseValidation(t *testing.T) {
	orig := &model.Request{Method: "GET", URL: "http://a/", Header: http.Header{}, Body: []byte("orig")}
	ok, err := buildRequest(orig, &requestEdit{Method: "post", URL: " https://b.example/x?y=1 ", Headers: "Host: b.example\nX: 1", Body: ptr("new")})
	if err != nil || ok.Method != "post" || ok.URL != "https://b.example/x?y=1" || string(ok.Body) != "new" || ok.Header.Get("X") != "1" {
		t.Fatalf("ok = %+v err=%v", ok, err)
	}
	for _, e := range []requestEdit{
		{Method: "BAD METHOD", URL: "http://a/"},
		{Method: "GET", URL: "ftp://a/"},
		{Method: "GET", URL: "http:///nohost"},
		{Method: "GET", URL: "/relative"},
		{Method: "GET", URL: "http://a/", Headers: "garbage"},
	} {
		if _, err := buildRequest(orig, &e); err == nil {
			t.Errorf("%+v should be rejected", e)
		}
	}
	oresp := &model.Response{StatusCode: 200, Header: http.Header{}}
	if _, err := buildResponse(oresp, &responseEdit{Status: 99}); err == nil {
		t.Error("status 99 must be rejected")
	}
	if _, err := buildResponse(oresp, &responseEdit{Status: 600}); err == nil {
		t.Error("status 600 must be rejected")
	}
	if r, err := buildResponse(oresp, &responseEdit{Status: 404, Headers: "A: b", Body: ptr("nope")}); err != nil || r.StatusCode != 404 || string(r.Body) != "nope" {
		t.Fatalf("resp = %+v %v", r, err)
	}
}

// --- API ---

type fakeRepeater struct {
	mu   sync.Mutex
	last *model.Request
}

func (f *fakeRepeater) Send(_ context.Context, req *model.Request) (*model.Exchange, error) {
	f.mu.Lock()
	f.last = req
	f.mu.Unlock()
	if req.Method == "INVALID" {
		return nil, model.ErrInvalidRequest
	}
	return &model.Exchange{ID: 42, Source: model.SourceRepeater, Method: req.Method, URL: req.URL, Host: "h", StatusCode: 200,
		RespHeaders: http.Header{"X-R": {"1"}}, RespBody: []byte("result"), RespBodySize: 6}, nil
}

type seedStore struct{ fakeStore }

func (seedStore) Get(_ context.Context, id int64) (*model.Exchange, error) {
	if id != 7 {
		return nil, model.ErrNotFound
	}
	return &model.Exchange{ID: 7, Method: "POST", URL: "https://api.example/v1?x=1", Host: "api.example", Path: "/v1?x=1",
		ReqHeaders: http.Header{"Content-Type": {"application/json"}}, ReqBody: []byte(`{"a":1}`), ReqBodySize: 7}, nil
}

func newAPI(t *testing.T) (http.Handler, *intercept.Manager, *fakeRepeater) {
	m := intercept.New(10 * time.Second)
	rep := &fakeRepeater{}
	s := New("127.0.0.1:0", Deps{Store: seedStore{}, Interceptor: m, Repeater: rep}, slog.New(slog.DiscardHandler))
	return s.server.Handler, m, rep
}

func call(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Host = "127.0.0.1:8081"
	r.Header.Set("X-Requested-With", "proxyscope")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestInterceptAPIFlow(t *testing.T) {
	h, m, _ := newAPI(t)

	if w := call(h, "PUT", "/api/intercept/settings", `{"request":true,"response":false}`); w.Code != 200 || !m.Settings().Request {
		t.Fatalf("settings: %d %s", w.Code, w.Body)
	}
	held := &model.Request{Method: "GET", URL: "http://x.test/a", Header: http.Header{"Host": {"x.test"}, "X-Orig": {"1"}}, Body: []byte("body")}
	done := make(chan model.Outcome)
	go func() { done <- m.HoldRequest(context.Background(), held) }()
	for i := 0; i < 200 && len(m.List()) == 0; i++ {
		time.Sleep(10 * time.Millisecond)
	}

	var st interceptState
	json.Unmarshal(call(h, "GET", "/api/intercept", "").Body.Bytes(), &st)
	if !st.Settings.Request || len(st.Pending) != 1 || st.TimeoutSeconds != 10 {
		t.Fatalf("state = %+v", st)
	}
	id := st.Pending[0].ID
	base := "/api/intercept/" + itoa(id)

	var pv pendingView
	json.Unmarshal(call(h, "GET", base, "").Body.Bytes(), &pv)
	if pv.Request.Method != "GET" || !strings.HasPrefix(pv.Request.Headers, "Host: x.test\n") || pv.Request.Body.Content != "body" || !pv.Request.Body.Editable {
		t.Fatalf("view = %+v", pv)
	}

	// An invalid edit is rejected and the item stays held.
	if w := call(h, "POST", base+"/forward", `{"request":{"method":"GET","url":"ftp://bad","headers":"","body":"x"}}`); w.Code != 400 {
		t.Fatalf("invalid edit = %d %s", w.Code, w.Body)
	}
	if len(m.List()) != 1 {
		t.Fatal("item must stay held after an invalid edit")
	}

	edit := `{"request":{"method":"PUT","url":"http://x.test/b","headers":"Host: x.test\nX-New: 2","body":"changed"}}`
	if w := call(h, "POST", base+"/forward", edit); w.Code != 204 {
		t.Fatalf("forward = %d %s", w.Code, w.Body)
	}
	out := <-done
	if !out.Edited || held.Method != "PUT" || held.URL != "http://x.test/b" || string(held.Body) != "changed" || held.Header.Get("X-New") != "2" {
		t.Fatalf("outcome %+v, request %+v", out, held)
	}
	if w := call(h, "POST", base+"/forward", ""); w.Code != 409 {
		t.Fatalf("second resolve = %d, want 409", w.Code)
	}
}

func TestInterceptAPIForwardAsIsAndDropAndResponseEdit(t *testing.T) {
	h, m, _ := newAPI(t)
	m.SetSettings(model.InterceptSettings{Request: true, Response: true})

	hold := func(f func() model.Outcome) (chan model.Outcome, string) {
		ch := make(chan model.Outcome, 1)
		go func() { ch <- f() }()
		for i := 0; i < 200 && len(m.List()) == 0; i++ {
			time.Sleep(10 * time.Millisecond)
		}
		return ch, "/api/intercept/" + itoa(m.List()[0].ID)
	}

	// As-is (empty body)
	ch, base := hold(func() model.Outcome {
		return m.HoldRequest(context.Background(), &model.Request{Method: "GET", URL: "http://a/", Header: http.Header{}})
	})
	call(h, "POST", base+"/forward", "")
	if out := <-ch; out.Verdict != model.VerdictForward || out.Edited {
		t.Fatalf("as-is = %+v", out)
	}

	// Drop
	ch, base = hold(func() model.Outcome {
		return m.HoldRequest(context.Background(), &model.Request{Method: "GET", URL: "http://a/", Header: http.Header{}})
	})
	call(h, "POST", base+"/drop", "")
	if out := <-ch; out.Verdict != model.VerdictDrop {
		t.Fatalf("drop = %+v", out)
	}

	// Response edit (gzip body shown decoded, edit replaces it and drops Content-Encoding)
	resp := &model.Response{StatusCode: 200, Header: http.Header{"Content-Encoding": {"gzip"}, "Content-Length": {"99"}}, Body: gz("compressed text")}
	ch, base = hold(func() model.Outcome {
		return m.HoldResponse(context.Background(), &model.Request{Method: "GET", URL: "http://a/", Header: http.Header{}}, resp)
	})
	var pv pendingView
	json.Unmarshal(call(h, "GET", base, "").Body.Bytes(), &pv)
	if pv.Response == nil || pv.Response.Body.Content != "compressed text" || pv.Response.Body.DecodedFrom != "gzip" || pv.Kind != model.PendingResponse {
		t.Fatalf("response view = %+v", pv)
	}
	edit := `{"response":{"status":201,"headers":"Content-Encoding: gzip\nX-Edited: 1","body":"plain now"}}`
	if w := call(h, "POST", base+"/forward", edit); w.Code != 204 {
		t.Fatalf("forward = %d %s", w.Code, w.Body)
	}
	out := <-ch
	if !out.Edited || resp.StatusCode != 201 || string(resp.Body) != "plain now" || resp.Header.Get("Content-Encoding") != "" || resp.Header.Get("X-Edited") != "1" {
		t.Fatalf("outcome %+v resp %+v", out, resp)
	}
}

func TestRepeaterAPI(t *testing.T) {
	h, _, rep := newAPI(t)

	var seed repeaterSeed
	w := call(h, "GET", "/api/exchanges/7/repeater", "")
	json.Unmarshal(w.Body.Bytes(), &seed)
	if w.Code != 200 || seed.Method != "POST" || seed.URL != "https://api.example/v1?x=1" || !strings.HasPrefix(seed.Headers, "Host: api.example\n") ||
		seed.Body.Content != `{"a":1}` || !seed.Body.Editable || seed.SourceID != 7 {
		t.Fatalf("seed = %d %+v", w.Code, seed)
	}
	if w := call(h, "GET", "/api/exchanges/99/repeater", ""); w.Code != 404 {
		t.Fatalf("missing = %d", w.Code)
	}

	// Body left as the original text -> original bytes are used
	send := `{"sourceId":7,"method":"POST","url":"https://api.example/v1","headers":"Host: api.example\nContent-Type: application/json","body":"{\"a\":1}"}`
	w = call(h, "POST", "/api/repeater/send", send)
	var d detailView
	json.Unmarshal(w.Body.Bytes(), &d)
	if w.Code != 200 || d.ID != 42 || d.Source != model.SourceRepeater || d.Response == nil || d.Response.Body.Content != "result" {
		t.Fatalf("send = %d %s", w.Code, w.Body)
	}
	if string(rep.last.Body) != `{"a":1}` || rep.last.URL != "https://api.example/v1" {
		t.Fatalf("sent = %+v", rep.last)
	}

	if w := call(h, "POST", "/api/repeater/send", `{"method":"GET","url":"ftp://x","headers":""}`); w.Code != 400 {
		t.Fatalf("bad url = %d", w.Code)
	}
	if w := call(h, "POST", "/api/repeater/send", `not json`); w.Code != 400 {
		t.Fatalf("bad json = %d", w.Code)
	}
	if w := call(h, "POST", "/api/repeater/send", `{"method":"INVALID","url":"http://x/","headers":""}`); w.Code != 400 {
		t.Fatalf("invalid request = %d", w.Code)
	}
}

func itoa(i int64) string { b, _ := json.Marshal(i); return string(b) }
