package proxy

import (
	"context"
	"crypto/x509"
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

	"proxyscope/internal/ca"
	"proxyscope/internal/model"
	"proxyscope/internal/outbound"
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
	u, sink, _ := startProxy(t, testCfg(maxBody, 2*time.Second, false))
	return &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(u)},
		Timeout:   5 * time.Second,
	}, sink
}

func testCfg(maxBody int64, headerTimeout time.Duration, insecure bool) Config {
	return Config{MaxBodyBytes: maxBody, Outbound: outbound.Config{DialTimeout: time.Second, HeaderTimeout: headerTimeout, InsecureUpstream: insecure}}
}

func withRootCAs(c Config, pool *x509.CertPool) Config {
	c.Outbound.RootCAs = pool
	return c
}

// startProxy serves a Proxy (with a fresh temporary CA) on a random port. An
// optional Interceptor enables the live-intercept pause points.
func startProxy(t *testing.T, cfg Config, icpt ...Interceptor) (*url.URL, *memSink, *ca.Authority) {
	t.Helper()
	var ic Interceptor
	if len(icpt) > 0 {
		ic = icpt[0]
	}
	return startProxyRules(t, cfg, ic, nil)
}

// startProxyRules is startProxy plus an explicit (possibly nil) RuleEngine,
// for tests that exercise match & replace.
func startProxyRules(t *testing.T, cfg Config, icpt Interceptor, re RuleEngine) (*url.URL, *memSink, *ca.Authority) {
	t.Helper()
	authority, _, err := ca.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sink := &memSink{}
	p := New(cfg, sink, authority, icpt, re, slog.New(slog.DiscardHandler))
	srv := httptest.NewServer(p)
	t.Cleanup(func() { p.Shutdown(context.Background()); srv.Close() })
	u, _ := url.Parse(srv.URL)
	// httptest listens on a random port, so the self-loop check must know it.
	p.selfHost, p.selfPort, _ = net.SplitHostPort(u.Host)
	return u, sink, authority
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
	u, _, _ := startProxy(t, testCfg(1<<10, 100*time.Millisecond, false))
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
