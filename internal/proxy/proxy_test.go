package proxy

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"proxyscope/internal/model"
)

type memSink struct {
	mu  sync.Mutex
	got []*model.Exchange
}

func (m *memSink) Save(_ context.Context, ex *model.Exchange) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.got = append(m.got, ex)
	return nil
}

func (m *memSink) last(t *testing.T) *model.Exchange {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.got) == 0 {
		t.Fatal("no exchange recorded")
	}
	return m.got[len(m.got)-1]
}

// newProxyClient starts a proxy on a random port and returns an http.Client
// that uses it, plus the sink that records exchanges.
func newProxyClient(t *testing.T, maxBody int64) (*http.Client, *memSink) {
	t.Helper()
	sink := &memSink{}
	p := New(Config{Addr: "127.0.0.1:0", MaxBodyBytes: maxBody, DialTimeout: time.Second, HeaderTimeout: 2 * time.Second},
		sink, slog.New(slog.DiscardHandler))
	srv := httptest.NewServer(p)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	// httptest listens on a random port, so the self-loop check must know it.
	p.selfHost, p.selfPort, _ = net.SplitHostPort(u.Host)
	return &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(u), DisableKeepAlives: false},
		Timeout:   5 * time.Second,
	}, sink
}

func TestForwardAndCapture(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Echo-Len", "x")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("echo:" + string(b)))
	}))
	defer up.Close()
	c, sink := newProxyClient(t, 1<<20)

	resp, err := c.Post(up.URL+"/path?q=1", "text/plain", strings.NewReader("hello"))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 201 || string(body) != "echo:hello" || resp.Header.Get("X-Echo-Len") != "x" {
		t.Fatalf("bad response: %d %q %v", resp.StatusCode, body, resp.Header)
	}
	ex := sink.last(t)
	if ex.Method != "POST" || ex.Path != "/path?q=1" || ex.StatusCode != 201 ||
		string(ex.ReqBody) != "hello" || string(ex.RespBody) != "echo:hello" || ex.Error != "" {
		t.Fatalf("bad exchange: %+v", ex)
	}
}

func TestChunkedRequestAndResponse(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if len(r.TransferEncoding) == 0 || r.TransferEncoding[0] != "chunked" {
			t.Errorf("upstream expected chunked request, got %v (len %d)", r.TransferEncoding, r.ContentLength)
		}
		f := w.(http.Flusher)
		w.Write([]byte("part1-"))
		f.Flush()
		w.Write([]byte("part2-" + string(b)))
	}))
	defer up.Close()
	c, sink := newProxyClient(t, 1<<20)

	// io.MultiReader hides the length, forcing chunked encoding.
	req, _ := http.NewRequest("POST", up.URL, io.MultiReader(strings.NewReader("ab"), strings.NewReader("cd")))
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "part1-part2-abcd" {
		t.Fatalf("body = %q", body)
	}
	ex := sink.last(t)
	if string(ex.ReqBody) != "abcd" || string(ex.RespBody) != "part1-part2-abcd" {
		t.Fatalf("bad capture: req=%q resp=%q", ex.ReqBody, ex.RespBody)
	}
}

func TestBodyTruncationStillForwardsEverything(t *testing.T) {
	big := strings.Repeat("x", 5000)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, big) }))
	defer up.Close()
	c, sink := newProxyClient(t, 100)

	resp, err := c.Get(up.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if len(body) != 5000 {
		t.Fatalf("client got %d bytes, want 5000", len(body))
	}
	ex := sink.last(t)
	if len(ex.RespBody) != 100 || ex.RespBodySize != 5000 || !ex.RespBodyTruncated() {
		t.Fatalf("stored %d of %d", len(ex.RespBody), ex.RespBodySize)
	}
}

func TestConnectionRefusedReturnsReadable502(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close() // nothing listens here any more
	c, sink := newProxyClient(t, 1<<20)

	resp, err := c.Get("http://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway || !strings.Contains(string(body), "could not connect") {
		t.Fatalf("got %d %q", resp.StatusCode, body)
	}
	if ex := sink.last(t); ex.StatusCode != 502 || ex.Error == "" {
		t.Fatalf("bad exchange: %+v", ex)
	}
}

func TestHeaderTimeoutReturns504(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(600 * time.Millisecond)
	}))
	defer up.Close()
	sink := &memSink{}
	p := New(Config{MaxBodyBytes: 1 << 10, DialTimeout: time.Second, HeaderTimeout: 100 * time.Millisecond}, sink, slog.New(slog.DiscardHandler))
	srv := httptest.NewServer(p)
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	p.selfHost, p.selfPort, _ = net.SplitHostPort(u.Host)
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(u)}, Timeout: 5 * time.Second}

	resp, err := c.Get(up.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want 504", resp.StatusCode)
	}
}

func TestConnectIsRejectedAndRecorded(t *testing.T) {
	c, sink := newProxyClient(t, 1<<10)
	_, err := c.Get("https://example.invalid/") // client issues CONNECT
	if err == nil {
		t.Fatal("expected error: CONNECT is unsupported")
	}
	if ex := sink.last(t); ex.Method != "CONNECT" || ex.StatusCode != 501 {
		t.Fatalf("bad exchange: %+v", ex)
	}
}

func TestNonProxyRequestGets400(t *testing.T) {
	c, _ := newProxyClient(t, 1<<10)
	tr := c.Transport.(*http.Transport)
	proxyURL, _ := tr.Proxy(nil)
	resp, err := http.Get(proxyURL.String() + "/") // plain request, not proxy-form
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}
