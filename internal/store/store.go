// Package store persists captured exchanges in SQLite.
//
// It uses modernc.org/sqlite (pure Go, no CGO) so the project builds the same
// way on Windows and Linux without a C toolchain.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver

	"proxyscope/internal/model"
)

// schemaVersion is stored in PRAGMA user_version. Bump it and add a migration
// step in migrate() whenever the schema changes.
const schemaVersion = 3

const schemaV1 = `
CREATE TABLE IF NOT EXISTS exchanges (
	id             INTEGER PRIMARY KEY AUTOINCREMENT,
	ts_ns          INTEGER NOT NULL,
	duration_ns    INTEGER NOT NULL,
	method         TEXT    NOT NULL,
	url            TEXT    NOT NULL,
	host           TEXT    NOT NULL,
	path           TEXT    NOT NULL,
	proto          TEXT    NOT NULL,
	req_headers    TEXT    NOT NULL,
	req_body       BLOB,
	req_body_size  INTEGER NOT NULL,
	status         INTEGER NOT NULL,
	resp_headers   TEXT    NOT NULL,
	resp_body      BLOB,
	resp_body_size INTEGER NOT NULL,
	error          TEXT    NOT NULL DEFAULT ''
);`

// schemaV2 (Phase 3) marks replayed traffic and intercept edits.
const schemaV2 = `
ALTER TABLE exchanges ADD COLUMN source      TEXT    NOT NULL DEFAULT 'proxy';
ALTER TABLE exchanges ADD COLUMN req_edited  INTEGER NOT NULL DEFAULT 0;
ALTER TABLE exchanges ADD COLUMN resp_edited INTEGER NOT NULL DEFAULT 0;
ALTER TABLE exchanges ADD COLUMN note        TEXT    NOT NULL DEFAULT '';`

// schemaV3 (Phase 4) marks traffic modified by a match & replace rule.
// rule_fired is a cheap flag for the history list; rules_applied is the full
// JSON array of rule ids (in firing order), fetched only for the detail view.
const schemaV3 = `
ALTER TABLE exchanges ADD COLUMN rule_fired    INTEGER NOT NULL DEFAULT 0;
ALTER TABLE exchanges ADD COLUMN rules_applied TEXT    NOT NULL DEFAULT '[]';`

// Store is a SQLite-backed exchange store. It is safe for concurrent use.
type Store struct {
	db *sql.DB
}

// Open opens (creating if needed) the database at path. Use ":memory:" for tests.
func Open(path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"
	if path == ":memory:" {
		dsn = "file::memory:"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	// A single connection serializes access and avoids SQLITE_BUSY between
	// the proxy (writer) and the UI (reader); it also keeps :memory: coherent.
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	var v int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&v); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if v > schemaVersion {
		return fmt.Errorf("database schema version %d is newer than supported (%d)", v, schemaVersion)
	}
	if v < 1 {
		if _, err := s.db.Exec(schemaV1); err != nil {
			return fmt.Errorf("create schema: %w", err)
		}
	}
	if v < 2 {
		// One transaction (including the version bump) so a crash cannot leave
		// half-added columns behind.
		tx, err := s.db.Begin()
		if err != nil {
			return fmt.Errorf("begin migration: %w", err)
		}
		defer tx.Rollback()
		if _, err := tx.Exec(schemaV2); err != nil {
			return fmt.Errorf("migrate to schema v2: %w", err)
		}
		if _, err := tx.Exec("PRAGMA user_version = 2"); err != nil {
			return fmt.Errorf("set schema version: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration: %w", err)
		}
	}
	if v < 3 {
		tx, err := s.db.Begin()
		if err != nil {
			return fmt.Errorf("begin migration: %w", err)
		}
		defer tx.Rollback()
		if _, err := tx.Exec(schemaV3); err != nil {
			return fmt.Errorf("migrate to schema v3: %w", err)
		}
		if _, err := tx.Exec("PRAGMA user_version = 3"); err != nil {
			return fmt.Errorf("set schema version: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit migration: %w", err)
		}
	}
	return nil
}

// Save inserts ex and sets ex.ID. It satisfies proxy.Sink.
func (s *Store) Save(ctx context.Context, ex *model.Exchange) error {
	source := ex.Source
	if source == "" {
		source = model.SourceProxy
	}
	reqH, err := json.Marshal(ex.ReqHeaders)
	if err != nil {
		return fmt.Errorf("encode request headers: %w", err)
	}
	respH, err := json.Marshal(ex.RespHeaders)
	if err != nil {
		return fmt.Errorf("encode response headers: %w", err)
	}
	rulesApplied, err := json.Marshal(nonNilStrings(ex.RulesApplied))
	if err != nil {
		return fmt.Errorf("encode rules applied: %w", err)
	}
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO exchanges (ts_ns, duration_ns, method, url, host, path, proto,
			req_headers, req_body, req_body_size, status, resp_headers, resp_body, resp_body_size, error,
			source, req_edited, resp_edited, note, rule_fired, rules_applied)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		ex.Timestamp.UnixNano(), int64(ex.Duration), ex.Method, ex.URL, ex.Host, ex.Path, ex.Proto,
		string(reqH), ex.ReqBody, ex.ReqBodySize, ex.StatusCode, string(respH), ex.RespBody, ex.RespBodySize, ex.Error,
		source, ex.ReqEdited, ex.RespEdited, ex.Note, ex.RuleFired(), string(rulesApplied))
	if err != nil {
		return fmt.Errorf("insert exchange: %w", err)
	}
	ex.ID, err = res.LastInsertId()
	return err
}

// List returns summaries in ascending id order. With afterID > 0 it returns
// rows newer than afterID (used for polling); with afterID == 0 it returns the
// most recent limit rows.
func (s *Store) List(ctx context.Context, afterID int64, limit int) ([]model.Summary, error) {
	const cols = `id, ts_ns, duration_ns, method, url, host, path, status, resp_body_size, error, source, (req_edited OR resp_edited) AS edited, rule_fired, note`
	var (
		rows *sql.Rows
		err  error
	)
	if afterID > 0 {
		rows, err = s.db.QueryContext(ctx,
			`SELECT `+cols+` FROM exchanges WHERE id > ? ORDER BY id ASC LIMIT ?`, afterID, limit)
	} else {
		rows, err = s.db.QueryContext(ctx,
			`SELECT id, ts_ns, duration_ns, method, url, host, path, status, resp_body_size, error, source, edited, rule_fired, note
			 FROM (SELECT `+cols+` FROM exchanges ORDER BY id DESC LIMIT ?) ORDER BY id ASC`, limit)
	}
	if err != nil {
		return nil, fmt.Errorf("list exchanges: %w", err)
	}
	defer rows.Close()

	out := []model.Summary{}
	for rows.Next() {
		var (
			m     model.Summary
			tsNs  int64
			durNs int64
		)
		if err := rows.Scan(&m.ID, &tsNs, &durNs, &m.Method, &m.URL, &m.Host, &m.Path, &m.StatusCode, &m.RespBodySize, &m.Error, &m.Source, &m.Edited, &m.RuleFired, &m.Note); err != nil {
			return nil, fmt.Errorf("scan exchange: %w", err)
		}
		m.Timestamp = time.Unix(0, tsNs)
		m.DurationMs = float64(durNs) / float64(time.Millisecond)
		out = append(out, m)
	}
	return out, rows.Err()
}

// Get returns the full exchange with the given id, or model.ErrNotFound.
func (s *Store) Get(ctx context.Context, id int64) (*model.Exchange, error) {
	var (
		ex           model.Exchange
		tsNs, durNs  int64
		reqH, respH  string
		rulesApplied string
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT id, ts_ns, duration_ns, method, url, host, path, proto,
			req_headers, req_body, req_body_size, status, resp_headers, resp_body, resp_body_size, error,
			source, req_edited, resp_edited, note, rules_applied
		 FROM exchanges WHERE id = ?`, id).
		Scan(&ex.ID, &tsNs, &durNs, &ex.Method, &ex.URL, &ex.Host, &ex.Path, &ex.Proto,
			&reqH, &ex.ReqBody, &ex.ReqBodySize, &ex.StatusCode, &respH, &ex.RespBody, &ex.RespBodySize, &ex.Error,
			&ex.Source, &ex.ReqEdited, &ex.RespEdited, &ex.Note, &rulesApplied)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, model.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get exchange %d: %w", id, err)
	}
	ex.Timestamp = time.Unix(0, tsNs)
	ex.Duration = time.Duration(durNs)
	if ex.ReqHeaders, err = decodeHeaders(reqH); err != nil {
		return nil, fmt.Errorf("decode request headers of %d: %w", id, err)
	}
	if ex.RespHeaders, err = decodeHeaders(respH); err != nil {
		return nil, fmt.Errorf("decode response headers of %d: %w", id, err)
	}
	if err := json.Unmarshal([]byte(rulesApplied), &ex.RulesApplied); err != nil {
		return nil, fmt.Errorf("decode rules applied of %d: %w", id, err)
	}
	return &ex, nil
}

// Clear deletes all stored exchanges. Ids are never reused (AUTOINCREMENT), so
// UI clients polling with a last-seen id keep working.
func (s *Store) Clear(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM exchanges`); err != nil {
		return fmt.Errorf("clear exchanges: %w", err)
	}
	return nil
}

// nonNilStrings returns s, or an empty (never nil) slice, so it encodes as
// JSON "[]" rather than "null".
func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func decodeHeaders(s string) (http.Header, error) {
	h := http.Header{}
	if err := json.Unmarshal([]byte(s), &h); err != nil {
		return nil, err
	}
	return h, nil
}
