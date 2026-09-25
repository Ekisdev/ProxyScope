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
const schemaVersion = 4

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

// schemaV4 (Phase 5) adds the generic TCP/UDP relay's own tables, separate
// from exchanges because the data shape is different (no method/URL/status,
// just raw byte chunks grouped into sessions). relay_sessions is one TCP
// connection or UDP client grouping; relay_chunks is every captured chunk,
// ordered by seq (both directions share one sequence per session, for a
// true chronological view). closed_at_ns is NULL while a session is open.
const schemaV4 = `
CREATE TABLE IF NOT EXISTS relay_sessions (
	id             INTEGER PRIMARY KEY AUTOINCREMENT,
	target         TEXT    NOT NULL,
	protocol       TEXT    NOT NULL,
	client_addr    TEXT    NOT NULL,
	upstream_addr  TEXT    NOT NULL,
	opened_at_ns   INTEGER NOT NULL,
	closed_at_ns   INTEGER,
	bytes_up       INTEGER NOT NULL DEFAULT 0,
	bytes_down     INTEGER NOT NULL DEFAULT 0,
	error          TEXT    NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS relay_chunks (
	id             INTEGER PRIMARY KEY AUTOINCREMENT,
	session_id     INTEGER NOT NULL REFERENCES relay_sessions(id),
	seq            INTEGER NOT NULL,
	direction      TEXT    NOT NULL,
	ts_ns          INTEGER NOT NULL,
	data           BLOB    NOT NULL,
	data_size      INTEGER NOT NULL,
	edited         INTEGER NOT NULL DEFAULT 0,
	note           TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS relay_chunks_session_idx ON relay_chunks(session_id, seq);`

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
	if v < 4 {
		tx, err := s.db.Begin()
		if err != nil {
			return fmt.Errorf("begin migration: %w", err)
		}
		defer tx.Rollback()
		if _, err := tx.Exec(schemaV4); err != nil {
			return fmt.Errorf("migrate to schema v4: %w", err)
		}
		if _, err := tx.Exec("PRAGMA user_version = 4"); err != nil {
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

// --- Relay (Phase 5) ---

const (
	defaultRelaySessionLimit = 200
	maxRelaySessionLimit     = 1000
	maxRelayChunkLimit       = 5000 // defensive cap: a long session can have many tiny chunks
)

// OpenSession inserts sess (which may already be closed, e.g. a dial
// failure recorded in one step) and sets sess.ID. It satisfies relay.Sink.
func (s *Store) OpenSession(ctx context.Context, sess *model.RelaySession) error {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO relay_sessions (target, protocol, client_addr, upstream_addr, opened_at_ns, closed_at_ns, bytes_up, bytes_down, error)
		 VALUES (?,?,?,?,?,?,?,?,?)`,
		sess.Target, string(sess.Protocol), sess.ClientAddr, sess.UpstreamAddr, sess.OpenedAt.UnixNano(),
		closedAtNs(sess.ClosedAt), sess.BytesUp, sess.BytesDown, sess.Error)
	if err != nil {
		return fmt.Errorf("insert relay session: %w", err)
	}
	sess.ID, err = res.LastInsertId()
	return err
}

// CloseSession records a session as finished. It satisfies relay.Sink.
func (s *Store) CloseSession(ctx context.Context, id int64, closedAt time.Time, bytesUp, bytesDown int64, errStr string) error {
	if _, err := s.db.ExecContext(ctx,
		`UPDATE relay_sessions SET closed_at_ns = ?, bytes_up = ?, bytes_down = ?, error = ? WHERE id = ?`,
		closedAt.UnixNano(), bytesUp, bytesDown, errStr, id); err != nil {
		return fmt.Errorf("close relay session %d: %w", id, err)
	}
	return nil
}

// SaveChunk inserts c and sets c.ID. It satisfies relay.Sink.
func (s *Store) SaveChunk(ctx context.Context, c *model.RelayChunk) error {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO relay_chunks (session_id, seq, direction, ts_ns, data, data_size, edited, note)
		 VALUES (?,?,?,?,?,?,?,?)`,
		c.SessionID, c.Seq, string(c.Direction), c.Timestamp.UnixNano(), c.Data, c.DataSize, c.Edited, c.Note)
	if err != nil {
		return fmt.Errorf("insert relay chunk: %w", err)
	}
	c.ID, err = res.LastInsertId()
	return err
}

// ListRelaySessions returns session summaries, newest first. target ""
// means every target; limit is clamped like List's for exchanges.
func (s *Store) ListRelaySessions(ctx context.Context, target string, limit int) ([]model.RelaySessionSummary, error) {
	if limit <= 0 {
		limit = defaultRelaySessionLimit
	}
	limit = min(limit, maxRelaySessionLimit)
	const cols = `id, target, protocol, client_addr, upstream_addr, opened_at_ns, closed_at_ns, bytes_up, bytes_down, error`
	var (
		rows *sql.Rows
		err  error
	)
	if target != "" {
		rows, err = s.db.QueryContext(ctx, `SELECT `+cols+` FROM relay_sessions WHERE target = ? ORDER BY id DESC LIMIT ?`, target, limit)
	} else {
		rows, err = s.db.QueryContext(ctx, `SELECT `+cols+` FROM relay_sessions ORDER BY id DESC LIMIT ?`, limit)
	}
	if err != nil {
		return nil, fmt.Errorf("list relay sessions: %w", err)
	}
	defer rows.Close()

	out := []model.RelaySessionSummary{}
	for rows.Next() {
		var (
			m        model.RelaySessionSummary
			protocol string
			openedNs int64
			closedNs sql.NullInt64
		)
		if err := rows.Scan(&m.ID, &m.Target, &protocol, &m.ClientAddr, &m.UpstreamAddr, &openedNs, &closedNs, &m.BytesUp, &m.BytesDown, &m.Error); err != nil {
			return nil, fmt.Errorf("scan relay session: %w", err)
		}
		m.Protocol = protocol
		m.OpenedAt = time.Unix(0, openedNs)
		if closedNs.Valid {
			c := time.Unix(0, closedNs.Int64)
			m.ClosedAt = &c
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// GetRelaySession returns one session, or model.ErrNotFound.
func (s *Store) GetRelaySession(ctx context.Context, id int64) (*model.RelaySession, error) {
	var (
		sess     model.RelaySession
		protocol string
		openedNs int64
		closedNs sql.NullInt64
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT id, target, protocol, client_addr, upstream_addr, opened_at_ns, closed_at_ns, bytes_up, bytes_down, error
		 FROM relay_sessions WHERE id = ?`, id).
		Scan(&sess.ID, &sess.Target, &protocol, &sess.ClientAddr, &sess.UpstreamAddr, &openedNs, &closedNs, &sess.BytesUp, &sess.BytesDown, &sess.Error)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, model.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get relay session %d: %w", id, err)
	}
	sess.Protocol = model.RelayProtocol(protocol)
	sess.OpenedAt = time.Unix(0, openedNs)
	if closedNs.Valid {
		sess.ClosedAt = time.Unix(0, closedNs.Int64)
	}
	return &sess, nil
}

// ListRelayChunks returns every captured chunk for sessionID, in capture
// order, up to a defensive limit (a long session can produce many tiny
// chunks; there is no pagination API for this yet).
func (s *Store) ListRelayChunks(ctx context.Context, sessionID int64) ([]model.RelayChunk, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, session_id, seq, direction, ts_ns, data, data_size, edited, note
		 FROM relay_chunks WHERE session_id = ? ORDER BY seq ASC LIMIT ?`, sessionID, maxRelayChunkLimit)
	if err != nil {
		return nil, fmt.Errorf("list relay chunks: %w", err)
	}
	defer rows.Close()

	out := []model.RelayChunk{}
	for rows.Next() {
		var (
			c         model.RelayChunk
			direction string
			tsNs      int64
		)
		if err := rows.Scan(&c.ID, &c.SessionID, &c.Seq, &direction, &tsNs, &c.Data, &c.DataSize, &c.Edited, &c.Note); err != nil {
			return nil, fmt.Errorf("scan relay chunk: %w", err)
		}
		c.Direction = model.RelayDirection(direction)
		c.Timestamp = time.Unix(0, tsNs)
		out = append(out, c)
	}
	return out, rows.Err()
}

func closedAtNs(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UnixNano()
}
