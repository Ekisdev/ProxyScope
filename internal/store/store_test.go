package store

import (
	"context"
	"database/sql"
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

func TestSchemaV1DatabaseIsMigrated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	// Build a schema-v1 database (as created by Phases 1-2) with one row.
	old, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.Exec(schemaV1); err != nil {
		t.Fatal(err)
	}
	_, err = old.Exec(`INSERT INTO exchanges (ts_ns, duration_ns, method, url, host, path, proto, req_headers, req_body_size, status, resp_headers, resp_body_size)
		VALUES (1, 2, 'GET', 'http://old/', 'old', '/', 'HTTP/1.1', '{}', 0, 200, '{}', 0)`)
	if err != nil {
		t.Fatal(err)
	}
	old.Exec("PRAGMA user_version = 1")
	old.Close()

	s, err := Open(path)
	if err != nil {
		t.Fatalf("migration failed: %v", err)
	}
	defer s.Close()
	ctx := context.Background()
	got, err := s.Get(ctx, 1)
	if err != nil || got.Source != model.SourceProxy || got.ReqEdited || got.Note != "" {
		t.Fatalf("migrated row = %+v err=%v", got, err)
	}

	// New columns work, and the summary reports replayed/edited/note.
	ex := sample(1)
	ex.Source, ex.RespEdited, ex.Note = model.SourceRepeater, true, "hello"
	if err := s.Save(ctx, ex); err != nil {
		t.Fatal(err)
	}
	all, _ := s.List(ctx, 0, 10)
	last := all[len(all)-1]
	if last.Source != model.SourceRepeater || !last.Edited || last.Note != "hello" || all[0].Source != model.SourceProxy || all[0].Edited {
		t.Fatalf("summaries = %+v", all)
	}
	full, _ := s.Get(ctx, ex.ID)
	if full.Source != model.SourceRepeater || !full.RespEdited || full.ReqEdited {
		t.Fatalf("full = %+v", full)
	}

	// Reopening a migrated database is a no-op.
	s.Close()
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	s2.Close()
}
