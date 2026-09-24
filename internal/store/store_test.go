package store

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"proxyscope/internal/model"
)

func sample(n int) *model.Exchange {
	return &model.Exchange{
		Timestamp:    time.Now(),
		Duration:     1500 * time.Microsecond,
		Method:       "GET",
		URL:          "http://example.com/" + string(rune('a'+n)),
		Host:         "example.com",
		Path:         "/" + string(rune('a'+n)),
		Proto:        "HTTP/1.1",
		ReqHeaders:   http.Header{"X-A": {"1", "2"}},
		ReqBody:      []byte{0, 1, 2},
		ReqBodySize:  3,
		StatusCode:   200,
		RespHeaders:  http.Header{"Content-Type": {"text/plain"}},
		RespBody:     []byte("hi"),
		RespBodySize: 10, // larger than stored: truncated
	}
}

func TestSaveGetListClear(t *testing.T) {
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	for i := 0; i < 3; i++ {
		ex := sample(i)
		if err := s.Save(ctx, ex); err != nil {
			t.Fatal(err)
		}
		if ex.ID != int64(i+1) {
			t.Fatalf("id = %d", ex.ID)
		}
	}

	got, err := s.Get(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	if got.Path != "/b" || got.ReqHeaders.Values("X-A")[1] != "2" || string(got.RespBody) != "hi" ||
		!got.RespBodyTruncated() || got.Duration != 1500*time.Microsecond || len(got.ReqBody) != 3 {
		t.Fatalf("round trip mismatch: %+v", got)
	}

	if _, err := s.Get(ctx, 99); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}

	all, _ := s.List(ctx, 0, 2) // most recent 2, ascending
	if len(all) != 2 || all[0].ID != 2 || all[1].ID != 3 {
		t.Fatalf("list latest = %+v", all)
	}
	newer, _ := s.List(ctx, 1, 100)
	if len(newer) != 2 || newer[0].ID != 2 {
		t.Fatalf("list after = %+v", newer)
	}

	if err := s.Clear(ctx); err != nil {
		t.Fatal(err)
	}
	ex := sample(0)
	s.Save(ctx, ex)
	if ex.ID != 4 {
		t.Fatalf("ids must not be reused after clear, got %d", ex.ID)
	}
}
