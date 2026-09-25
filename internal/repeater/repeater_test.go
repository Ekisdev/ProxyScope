package repeater

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

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
	ex.ID = int64(len(m.got) + 1)
	m.got = append(m.got, ex)
	return nil
}

func newService(insecure bool, max int64) (*Service, *memSink) {
	sink := &memSink{}
	return New(Config{MaxBodyBytes: max, Outbound: outbound.Config{
		DialTimeout: time.Second, HeaderTimeout: 500 * time.Millisecond, InsecureUpstream: insecure,
	}}, sink), sink
}

func TestSendStoresReplayedExchange(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Seen-Host", r.Host)
		w.WriteHeader(201)
		io.WriteString(w, r.Method+" "+r.URL.RequestURI()+" "+r.Header.Get("X-A")+" "+string(b))
	}))
	defer up.Close()
	s, sink := newService(false, 1<<20)

	ex, err := s.Send(context.Background(), &model.Request{
		Method: "POST", URL: up.URL + "/p?q=1",
		Header: http.Header{"X-A": {"1"}, "Host": {"virtual.example"}, "Content-Length": {"999"}},
		Body:   []byte("data"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if ex.ReqHeaders.Get("Content-Length") != "4" {
		t.Fatalf("stored Content-Length must match the body actually sent: %v", ex.ReqHeaders)
	}
	if ex.Source != model.SourceRepeater || ex.ID == 0 || ex.StatusCode != 201 || string(ex.RespBody) != "POST /p?q=1 1 data" ||
		ex.RespHeaders.Get("X-Seen-Host") != "virtual.example" || string(ex.ReqBody) != "data" || ex.Error != "" {
		t.Fatalf("exchange = %+v", ex)
	}
	if len(sink.got) != 1 {
		t.Fatal("result must be stored in history")
	}
}

func TestSendDoesNotFollowRedirects(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	}))
	defer up.Close()
	s, _ := newService(false, 1<<20)
	ex, _ := s.Send(context.Background(), &model.Request{Method: "GET", URL: up.URL + "/", Header: http.Header{}})
	if ex.StatusCode != 302 || ex.RespHeaders.Get("Location") != "/elsewhere" {
		t.Fatalf("exchange = %+v", ex)
	}
}

func TestSendUnreachableIsAResultNotAGoError(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	s, sink := newService(false, 1<<20)
	ex, err := s.Send(context.Background(), &model.Request{Method: "GET", URL: "http://" + addr + "/", Header: http.Header{}})
	if err != nil {
		t.Fatal(err)
	}
	if ex.StatusCode != 0 || !strings.Contains(ex.Error, "could not connect") || len(sink.got) != 1 {
		t.Fatalf("exchange = %+v", ex)
	}
}

func TestSendTimeoutIsReadable(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(1500 * time.Millisecond) }))
	defer up.Close()
	s, _ := newService(false, 1<<20)
	ex, _ := s.Send(context.Background(), &model.Request{Method: "GET", URL: up.URL, Header: http.Header{}})
	if !strings.Contains(ex.Error, "timed out") {
		t.Fatalf("error = %q", ex.Error)
	}
}

func TestSendInvalidRequests(t *testing.T) {
	s, sink := newService(false, 1<<20)
	for _, r := range []*model.Request{
		{Method: "GET", URL: "ftp://x/", Header: http.Header{}},
		{Method: "GET", URL: "/relative", Header: http.Header{}},
		{Method: "BAD METHOD", URL: "http://x/", Header: http.Header{}},
	} {
		if _, err := s.Send(context.Background(), r); !errors.Is(err, model.ErrInvalidRequest) {
			t.Errorf("%+v: err = %v", r, err)
		}
	}
	if len(sink.got) != 0 {
		t.Fatal("invalid requests must not be stored")
	}
}

func TestSendHTTPSValidationFollowsFlag(t *testing.T) {
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer up.Close()
	req := &model.Request{Method: "GET", URL: up.URL + "/", Header: http.Header{}}

	strict, _ := newService(false, 1<<20)
	if ex, _ := strict.Send(context.Background(), req); !strings.Contains(ex.Error, "failed validation") {
		t.Fatalf("validation must be on by default: %+v", ex)
	}
	lax, _ := newService(true, 1<<20)
	if ex, _ := lax.Send(context.Background(), req); ex.StatusCode != 200 || string(ex.RespBody) != "ok" {
		t.Fatalf("insecure-upstream must accept the cert: %+v", ex)
	}
}

func TestSendCapsStoredBodiesButReportsRealSize(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, strings.Repeat("x", 1000))
	}))
	defer up.Close()
	s, _ := newService(false, 100)
	ex, _ := s.Send(context.Background(), &model.Request{Method: "GET", URL: up.URL, Header: http.Header{}})
	if len(ex.RespBody) != 100 || ex.RespBodySize != 1000 || !ex.RespBodyTruncated() {
		t.Fatalf("stored %d of %d", len(ex.RespBody), ex.RespBodySize)
	}
}
