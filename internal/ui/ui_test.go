package ui

import (
	"bytes"
	"compress/gzip"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"proxyscope/internal/model"
)

func TestRenderBodyGzipTextAndBinary(t *testing.T) {
	var zb bytes.Buffer
	zw := gzip.NewWriter(&zb)
	zw.Write([]byte("héllo world"))
	zw.Close()

	v := renderBody(http.Header{"Content-Encoding": {"gzip"}}, zb.Bytes(), int64(zb.Len()))
	if v.Encoding != "text" || v.Content != "héllo world" || v.DecodedFrom != "gzip" {
		t.Fatalf("gzip view = %+v", v)
	}

	v = renderBody(http.Header{}, []byte{0x00, 0xff, 0x10}, 3)
	if v.Encoding != "hex" || !strings.Contains(v.Content, "00 ff 10") {
		t.Fatalf("binary view = %+v", v)
	}

	// Truncated in the middle of a multi-byte rune still renders as text.
	full := []byte("aé")
	v = renderBody(http.Header{}, full[:2], 3)
	if v.Encoding != "text" || v.Content != "a" || !v.Truncated {
		t.Fatalf("truncated view = %+v", v)
	}
}

type fakeStore struct{}

func (fakeStore) List(context.Context, int64, int) ([]model.Summary, error) {
	return []model.Summary{{ID: 1}}, nil
}
func (fakeStore) Get(context.Context, int64) (*model.Exchange, error) { return nil, model.ErrNotFound }
func (fakeStore) Clear(context.Context) error                         { return nil }

func TestGuardAndRoutes(t *testing.T) {
	s := New("127.0.0.1:0", Deps{Store: fakeStore{}, CAPEM: []byte("CERT")}, slog.New(slog.DiscardHandler))
	h := s.server.Handler
	do := func(method, path, host string, hdr map[string]string) int {
		r := httptest.NewRequest(method, path, nil)
		r.Host = host
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	xr := map[string]string{"X-Requested-With": "proxyscope"}

	if c := do("GET", "/", "127.0.0.1:8081", nil); c != 200 {
		t.Errorf("index = %d", c)
	}
	if c := do("GET", "/ca.crt", "127.0.0.1:8081", nil); c != 200 {
		t.Errorf("ca.crt = %d", c)
	}
	if c := do("GET", "/api/exchanges", "127.0.0.1:8081", nil); c != 200 {
		t.Errorf("list = %d", c)
	}
	if c := do("GET", "/api/exchanges/7", "localhost:8081", nil); c != 404 {
		t.Errorf("missing = %d", c)
	}
	if c := do("GET", "/api/exchanges", "evil.example:8081", nil); c != 403 {
		t.Errorf("rebinding host = %d, want 403", c)
	}
	if c := do("DELETE", "/api/exchanges", "127.0.0.1:8081", nil); c != 403 {
		t.Errorf("clear without header = %d, want 403", c)
	}
	if c := do("DELETE", "/api/exchanges", "127.0.0.1:8081", xr); c != 204 {
		t.Errorf("clear = %d, want 204", c)
	}
}
