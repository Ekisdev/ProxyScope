package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"proxyscope/internal/intercept"
	"proxyscope/internal/model"
)

// echoUpstream replies "<method> <uri> <X-Test> body=<body>" and counts hits.
func echoUpstream(t *testing.T, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		b, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Up", "yes")
		io.WriteString(w, r.Method+" "+r.URL.RequestURI()+" "+r.Header.Get("X-Test")+" body="+string(b))
	}))
	t.Cleanup(up.Close)
	return up
}

func waitHeld(t *testing.T, m *intercept.Manager, n int) []model.PendingSummary {
	t.Helper()
	for i := 0; i < 300; i++ {
		if l := m.List(); len(l) == n {
			return l
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("expected %d held items, have %d", n, len(m.List()))
	return nil
}

type result struct {
	status int
	body   string
	err    error
}

func async(c *http.Client, method, u, body string) <-chan result {
	ch := make(chan result, 1)
	go func() {
		req, _ := http.NewRequest(method, u, strings.NewReader(body))
		resp, err := c.Do(req)
		if err != nil {
			ch <- result{err: err}
			return
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		ch <- result{status: resp.StatusCode, body: string(b)}
	}()
	return ch
}

func get(t *testing.T, ch <-chan result) result {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("request did not complete")
		return result{}
	}
}

func setup(t *testing.T, timeout time.Duration, maxBody int64) (*http.Client, *memSink, *intercept.Manager) {
	t.Helper()
	m := intercept.New(timeout)
	u, sink, _ := startProxy(t, testCfg(maxBody, 2*time.Second, false), m)
	return &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(u)}, Timeout: 8 * time.Second}, sink, m
}

func TestInterceptOffByDefaultDoesNotPause(t *testing.T) {
	var hits atomic.Int32
	up := echoUpstream(t, &hits)
	c, _, m := setup(t, time.Minute, 1<<20)
	if r := get(t, async(c, "GET", up.URL+"/x", "")); r.status != 200 {
		t.Fatalf("got %+v", r)
	}
	if len(m.List()) != 0 {
		t.Fatal("nothing should be held")
	}
}

func TestRequestForwardAsIs(t *testing.T) {
	var hits atomic.Int32
	up := echoUpstream(t, &hits)
	c, sink, m := setup(t, time.Minute, 1<<20)
	m.SetSettings(model.InterceptSettings{Request: true})

	ch := async(c, "POST", up.URL+"/a", "payload")
	l := waitHeld(t, m, 1)
	if hits.Load() != 0 {
		t.Fatal("request reached the server while held")
	}
	p, _ := m.Get(l[0].ID)
	if p.Request.Method != "POST" || string(p.Request.Body) != "payload" || p.Request.Header.Get("Host") == "" {
		t.Fatalf("held request = %+v", p.Request)
	}
	m.Resolve(l[0].ID, model.Resolution{})
	if r := get(t, ch); r.status != 200 || !strings.HasSuffix(r.body, "body=payload") {
		t.Fatalf("got %+v", r)
	}
	if ex := sink.last(t); ex.ReqEdited || ex.Note != "" || string(ex.ReqBody) != "payload" {
		t.Fatalf("exchange = %+v", ex)
	}
}

func TestRequestEditedIsWhatIsSentAndStored(t *testing.T) {
	var hits atomic.Int32
	up := echoUpstream(t, &hits)
	c, sink, m := setup(t, time.Minute, 1<<20)
	m.SetSettings(model.InterceptSettings{Request: true})

	ch := async(c, "POST", up.URL+"/a", "old")
	l := waitHeld(t, m, 1)
	p, _ := m.Get(l[0].ID)
	e := p.Request.Clone()
	e.Method, e.URL, e.Body = "PUT", up.URL+"/edited?x=1", []byte("brand new body")
	e.Header.Set("X-Test", "injected")
	m.Resolve(l[0].ID, model.Resolution{Request: e})

	r := get(t, ch)
	if r.body != "PUT /edited?x=1 injected body=brand new body" {
		t.Fatalf("upstream saw %q", r.body)
	}
	ex := sink.last(t)
	if !ex.ReqEdited || ex.Method != "PUT" || ex.Path != "/edited?x=1" || string(ex.ReqBody) != "brand new body" ||
		ex.ReqHeaders.Get("X-Test") != "injected" || ex.ReqHeaders.Get("Host") != "" ||
		ex.ReqHeaders.Get("Content-Length") != "14" {
		t.Fatalf("stored exchange should describe what was sent: %+v", ex)
	}
}

func TestRequestEditToAnotherHost(t *testing.T) {
	var h1, h2 atomic.Int32
	up1, up2 := echoUpstream(t, &h1), echoUpstream(t, &h2)
	c, _, m := setup(t, time.Minute, 1<<20)
	m.SetSettings(model.InterceptSettings{Request: true})

	ch := async(c, "GET", up1.URL+"/", "")
	l := waitHeld(t, m, 1)
	p, _ := m.Get(l[0].ID)
	e := p.Request.Clone()
	e.URL = up2.URL + "/redirected"
	e.Header.Set("Host", strings.TrimPrefix(up2.URL, "http://"))
	m.Resolve(l[0].ID, model.Resolution{Request: e})
	if r := get(t, ch); !strings.HasPrefix(r.body, "GET /redirected") || h1.Load() != 0 || h2.Load() != 1 {
		t.Fatalf("got %+v hits=%d/%d", r, h1.Load(), h2.Load())
	}
}

func TestRequestDrop(t *testing.T) {
	var hits atomic.Int32
	up := echoUpstream(t, &hits)
	c, sink, m := setup(t, time.Minute, 1<<20)
	m.SetSettings(model.InterceptSettings{Request: true})

	ch := async(c, "GET", up.URL+"/", "")
	l := waitHeld(t, m, 1)
	m.Resolve(l[0].ID, model.Resolution{Drop: true})
	r := get(t, ch)
	if r.status != http.StatusForbidden || !strings.Contains(r.body, "dropped") || hits.Load() != 0 {
		t.Fatalf("got %+v hits=%d", r, hits.Load())
	}
	if ex := sink.last(t); ex.StatusCode != 403 || ex.Error == "" {
		t.Fatalf("exchange = %+v", ex)
	}
}

func TestHeldRequestsDoNotBlockEachOther(t *testing.T) {
	var hits atomic.Int32
	up := echoUpstream(t, &hits)
	c, _, m := setup(t, time.Minute, 1<<20)
	m.SetSettings(model.InterceptSettings{Request: true})

	a := async(c, "GET", up.URL+"/a", "")
	l := waitHeld(t, m, 1) // hold a first so the ids are ordered
	idA := l[0].ID
	b := async(c, "GET", up.URL+"/b", "")
	l = waitHeld(t, m, 2)
	idB := l[1].ID

	// Release b while a stays held: b completes, a is still waiting.
	m.Resolve(idB, model.Resolution{})
	if r := get(t, b); r.status != 200 || !strings.Contains(r.body, "GET /b") {
		t.Fatalf("b = %+v", r)
	}
	select {
	case r := <-a:
		t.Fatalf("a must still be held, but completed: %+v", r)
	case <-time.After(150 * time.Millisecond):
	}
	if l := m.List(); len(l) != 1 || l[0].ID != idA {
		t.Fatalf("held = %+v", l)
	}
	m.Resolve(idA, model.Resolution{})
	if r := get(t, a); !strings.Contains(r.body, "GET /a") {
		t.Fatalf("a = %+v", r)
	}
}

func TestTimeoutAutoForwardsWithNote(t *testing.T) {
	var hits atomic.Int32
	up := echoUpstream(t, &hits)
	c, sink, m := setup(t, 150*time.Millisecond, 1<<20)
	m.SetSettings(model.InterceptSettings{Request: true})
	start := time.Now()
	r := get(t, async(c, "GET", up.URL+"/", ""))
	if r.status != 200 || time.Since(start) < 120*time.Millisecond {
		t.Fatalf("got %+v after %v", r, time.Since(start))
	}
	if ex := sink.last(t); !strings.Contains(ex.Note, "auto-forwarded") {
		t.Fatalf("note = %q", ex.Note)
	}
}

func TestClientDisconnectRemovesHeldRequest(t *testing.T) {
	var hits atomic.Int32
	up := echoUpstream(t, &hits)
	m := intercept.New(time.Minute)
	pu, sink, _ := startProxy(t, testCfg(1<<20, 2*time.Second, false), m)
	m.SetSettings(model.InterceptSettings{Request: true})
	ctx, cancel := context.WithCancel(context.Background())
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu)}}
	go func() {
		req, _ := http.NewRequestWithContext(ctx, "GET", up.URL+"/", nil)
		c.Do(req)
	}()
	waitHeld(t, m, 1)
	cancel()
	waitHeld(t, m, 0)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		sink.mu.Lock()
		n := len(sink.got)
		sink.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if ex := sink.last(t); ex.StatusCode != 0 || !strings.Contains(ex.Error, "disconnected") || hits.Load() != 0 {
		t.Fatalf("exchange = %+v hits=%d", ex, hits.Load())
	}
}

func TestOversizedRequestBodyIsNotHeld(t *testing.T) {
	var hits atomic.Int32
	up := echoUpstream(t, &hits)
	c, sink, m := setup(t, time.Minute, 10) // -max-body = 10
	m.SetSettings(model.InterceptSettings{Request: true})
	big := strings.Repeat("z", 100)
	r := get(t, async(c, "POST", up.URL+"/", big))
	if r.status != 200 || !strings.HasSuffix(r.body, "body="+big) {
		t.Fatalf("body must still be forwarded completely: %+v", r)
	}
	if ex := sink.last(t); !strings.Contains(ex.Note, "not intercepted") || ex.ReqBodySize != 100 || len(ex.ReqBody) != 10 {
		t.Fatalf("exchange = %+v", ex)
	}
	if len(m.List()) != 0 {
		t.Fatal("oversized request must not be held")
	}
}

func TestResponseEditDropAndStreamingSkip(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sse":
			w.Header().Set("Content-Type", "text/event-stream")
			io.WriteString(w, "data: 1\n\n")
		default:
			w.Header().Set("Content-Type", "text/plain")
			io.WriteString(w, "original body")
		}
	}))
	defer up.Close()
	c, sink, m := setup(t, time.Minute, 1<<20)
	m.SetSettings(model.InterceptSettings{Response: true})

	// Edit
	ch := async(c, "GET", up.URL+"/", "")
	l := waitHeld(t, m, 1)
	p, _ := m.Get(l[0].ID)
	if l[0].Kind != model.PendingResponse || string(p.Response.Body) != "original body" {
		t.Fatalf("held = %+v", p)
	}
	e := p.Response.Clone()
	e.StatusCode, e.Body = 418, []byte("edited!")
	e.Header.Set("X-Added", "1")
	m.Resolve(l[0].ID, model.Resolution{Response: e})
	r := get(t, ch)
	if r.status != 418 || r.body != "edited!" {
		t.Fatalf("client got %+v", r)
	}
	if ex := sink.last(t); !ex.RespEdited || ex.StatusCode != 418 || string(ex.RespBody) != "edited!" || ex.RespHeaders.Get("X-Added") != "1" {
		t.Fatalf("exchange = %+v", ex)
	}

	// Drop
	ch = async(c, "GET", up.URL+"/", "")
	l = waitHeld(t, m, 1)
	m.Resolve(l[0].ID, model.Resolution{Drop: true})
	if r := get(t, ch); r.status != 403 || !strings.Contains(r.body, "dropped") {
		t.Fatalf("got %+v", r)
	}

	// Streaming responses are not held
	r = get(t, async(c, "GET", up.URL+"/sse", ""))
	if r.status != 200 || !strings.Contains(r.body, "data: 1") {
		t.Fatalf("got %+v", r)
	}
	if ex := sink.last(t); !strings.Contains(ex.Note, "streaming") {
		t.Fatalf("note = %q", ex.Note)
	}
}

func TestHTTPSRequestsShareThePausePoint(t *testing.T) {
	up := newTLSUpstream(t)
	m := intercept.New(time.Minute)
	pu, sink, authority := startProxy(t, testCfg(1<<20, 2*time.Second, true), m)
	m.SetSettings(model.InterceptSettings{Request: true, Response: true})
	c := httpsClient(pu, caPool(authority))

	ch := async(c, "POST", up.URL+"/secure", "s3cret")
	l := waitHeld(t, m, 1)
	p, _ := m.Get(l[0].ID)
	if !strings.HasPrefix(p.Request.URL, "https://") || string(p.Request.Body) != "s3cret" {
		t.Fatalf("held = %+v", p.Request)
	}
	e := p.Request.Clone()
	e.Body = []byte("changed")
	m.Resolve(l[0].ID, model.Resolution{Request: e})
	l = waitHeld(t, m, 1) // now the response is held
	if l[0].Kind != model.PendingResponse {
		t.Fatalf("expected a held response, got %+v", l[0])
	}
	m.Resolve(l[0].ID, model.Resolution{})
	r := get(t, ch)
	if r.status != 200 || r.body != "secure:/secure:changed" {
		t.Fatalf("got %+v", r)
	}
	if ex := sink.last(t); !ex.ReqEdited || !strings.HasPrefix(ex.URL, "https://") {
		t.Fatalf("exchange = %+v", ex)
	}
}
