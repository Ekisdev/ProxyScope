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
		RulesApplied: []string{"rule-" + string(rune('a'+n))},
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
	if !got.RuleFired() || len(got.RulesApplied) != 1 || got.RulesApplied[0] != "rule-b" {
		t.Fatalf("rules applied round trip mismatch: %+v", got.RulesApplied)
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
	if err != nil || got.Source != model.SourceProxy || got.ReqEdited || got.Note != "" || got.RuleFired() {
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

func TestSchemaV2DatabaseIsMigrated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	// Build a schema-v2 database (as created by Phase 3) with one row.
	old, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.Exec(schemaV1); err != nil {
		t.Fatal(err)
	}
	if _, err := old.Exec(schemaV2); err != nil {
		t.Fatal(err)
	}
	_, err = old.Exec(`INSERT INTO exchanges (ts_ns, duration_ns, method, url, host, path, proto, req_headers, req_body_size, status, resp_headers, resp_body_size, source, req_edited, resp_edited, note)
		VALUES (1, 2, 'GET', 'http://old/', 'old', '/', 'HTTP/1.1', '{}', 0, 200, '{}', 0, 'proxy', 0, 0, '')`)
	if err != nil {
		t.Fatal(err)
	}
	old.Exec("PRAGMA user_version = 2")
	old.Close()

	s, err := Open(path)
	if err != nil {
		t.Fatalf("migration failed: %v", err)
	}
	defer s.Close()
	ctx := context.Background()
	got, err := s.Get(ctx, 1)
	if err != nil || got.RuleFired() || len(got.RulesApplied) != 0 {
		t.Fatalf("migrated row = %+v err=%v", got, err)
	}

	ex := sample(0)
	if err := s.Save(ctx, ex); err != nil {
		t.Fatal(err)
	}
	all, _ := s.List(ctx, 0, 10)
	if all[0].RuleFired || !all[1].RuleFired {
		t.Fatalf("summaries = %+v", all)
	}
}

func TestSchemaV3DatabaseIsMigrated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	// Build a schema-v3 database (as created by Phase 4) with one row.
	old, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	for _, ddl := range []string{schemaV1, schemaV2, schemaV3} {
		if _, err := old.Exec(ddl); err != nil {
			t.Fatal(err)
		}
	}
	_, err = old.Exec(`INSERT INTO exchanges (ts_ns, duration_ns, method, url, host, path, proto, req_headers, req_body_size, status, resp_headers, resp_body_size, source, req_edited, resp_edited, note, rule_fired, rules_applied)
		VALUES (1, 2, 'GET', 'http://old/', 'old', '/', 'HTTP/1.1', '{}', 0, 200, '{}', 0, 'proxy', 0, 0, '', 0, '[]')`)
	if err != nil {
		t.Fatal(err)
	}
	old.Exec("PRAGMA user_version = 3")
	old.Close()

	s, err := Open(path)
	if err != nil {
		t.Fatalf("migration failed: %v", err)
	}
	defer s.Close()
	ctx := context.Background()

	// The old exchange row is untouched, and the new relay tables work.
	if _, err := s.Get(ctx, 1); err != nil {
		t.Fatalf("old row: %v", err)
	}
	sess := &model.RelaySession{Target: "t1", Protocol: model.RelayTCP, ClientAddr: "1.2.3.4:5", UpstreamAddr: "up:1", OpenedAt: time.Now()}
	if err := s.OpenSession(ctx, sess); err != nil || sess.ID == 0 {
		t.Fatalf("OpenSession: %v %+v", err, sess)
	}
	sessions, _ := s.ListRelaySessions(ctx, "", 10)
	if len(sessions) != 1 || sessions[0].ID != sess.ID {
		t.Fatalf("sessions after migration = %+v", sessions)
	}
}

func TestRelaySessionAndChunkRoundTrip(t *testing.T) {
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	sess := &model.RelaySession{
		Target: "game1", Protocol: model.RelayTCP, ClientAddr: "127.0.0.1:1111",
		UpstreamAddr: "game.example.com:9100", OpenedAt: time.Now(),
	}
	if err := s.OpenSession(ctx, sess); err != nil {
		t.Fatal(err)
	}
	if sess.ID != 1 {
		t.Fatalf("id = %d", sess.ID)
	}

	// Still open: not returned as closed, ClosedAt is nil in the summary.
	list, err := s.ListRelaySessions(ctx, "game1", 10)
	if err != nil || len(list) != 1 || list[0].ClosedAt != nil {
		t.Fatalf("list (open) = %+v err=%v", list, err)
	}

	up := &model.RelayChunk{SessionID: sess.ID, Seq: 1, Direction: model.RelayUp, Timestamp: time.Now(), Data: []byte("hello"), DataSize: 5}
	down := &model.RelayChunk{SessionID: sess.ID, Seq: 2, Direction: model.RelayDown, Timestamp: time.Now(), Data: []byte("hi"), DataSize: 100, Edited: true, Note: "capped"}
	if err := s.SaveChunk(ctx, up); err != nil || up.ID == 0 {
		t.Fatalf("SaveChunk up: %v %+v", err, up)
	}
	if err := s.SaveChunk(ctx, down); err != nil || down.ID == 0 {
		t.Fatalf("SaveChunk down: %v %+v", err, down)
	}

	chunks, err := s.ListRelayChunks(ctx, sess.ID)
	if err != nil || len(chunks) != 2 {
		t.Fatalf("chunks = %+v err=%v", chunks, err)
	}
	if chunks[0].Direction != model.RelayUp || string(chunks[0].Data) != "hello" || chunks[0].DataTruncated() {
		t.Fatalf("chunk 0 = %+v", chunks[0])
	}
	if chunks[1].Direction != model.RelayDown || !chunks[1].Edited || chunks[1].Note != "capped" || !chunks[1].DataTruncated() {
		t.Fatalf("chunk 1 = %+v", chunks[1])
	}

	if err := s.CloseSession(ctx, sess.ID, time.Now(), 5, 2, ""); err != nil {
		t.Fatal(err)
	}
	full, err := s.GetRelaySession(ctx, sess.ID)
	if err != nil || full.ClosedAt.IsZero() || full.BytesUp != 5 || full.BytesDown != 2 {
		t.Fatalf("get after close = %+v err=%v", full, err)
	}
	list, _ = s.ListRelaySessions(ctx, "", 10)
	if len(list) != 1 || list[0].ClosedAt == nil {
		t.Fatalf("list (closed) = %+v", list)
	}

	if _, err := s.GetRelaySession(ctx, 999); !errors.Is(err, model.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}

	// A different target is excluded by the target filter.
	other := &model.RelaySession{Target: "game2", Protocol: model.RelayUDP, ClientAddr: "x", UpstreamAddr: "y", OpenedAt: time.Now()}
	s.OpenSession(ctx, other)
	filtered, _ := s.ListRelaySessions(ctx, "game1", 10)
	if len(filtered) != 1 {
		t.Fatalf("target filter leaked: %+v", filtered)
	}
}
