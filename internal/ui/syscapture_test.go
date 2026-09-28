package ui

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http/httptest"
	"testing"
	"time"

	"proxyscope/internal/model"
	"proxyscope/internal/sysCapture"
)

// fakeSysCapture is a minimal ui.SysCaptureStatus for exercising the HTTP
// handlers in isolation from the real sysCapture.Service (which requires
// WinDivert and cannot run in this environment) -- the hold queue/session
// logic itself is covered by internal/sysCapture's own test suite; this
// tests the routing/error-translation layer in ui/syscapture.go.
type fakeSysCapture struct {
	filter    string
	elevated  bool
	settings  model.RelaySettings
	pending   map[int64]*model.RelayPending
	resolveFn func(id int64, res model.RelayResolution) error
}

func (f *fakeSysCapture) Filter() string                    { return f.filter }
func (f *fakeSysCapture) Elevated() bool                    { return f.elevated }
func (f *fakeSysCapture) Timeout() time.Duration            { return 30 * time.Second }
func (f *fakeSysCapture) Settings() model.RelaySettings     { return f.settings }
func (f *fakeSysCapture) SetSettings(s model.RelaySettings) { f.settings = s }
func (f *fakeSysCapture) List() []model.RelayPendingSummary {
	out := make([]model.RelayPendingSummary, 0, len(f.pending))
	for _, p := range f.pending {
		out = append(out, p.RelayPendingSummary)
	}
	return out
}
func (f *fakeSysCapture) Get(id int64) (*model.RelayPending, error) {
	p, ok := f.pending[id]
	if !ok {
		return nil, model.ErrPendingGone
	}
	return p, nil
}
func (f *fakeSysCapture) Resolve(id int64, res model.RelayResolution) error {
	if f.resolveFn != nil {
		return f.resolveFn(id, res)
	}
	if _, ok := f.pending[id]; !ok {
		return model.ErrPendingGone
	}
	delete(f.pending, id)
	return nil
}

func TestSysCaptureStateReportsDisabledWhenNil(t *testing.T) {
	s := New("127.0.0.1:0", Deps{Store: fakeStore{}}, slog.New(slog.DiscardHandler))
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/syscapture", nil)
	r.Host = "127.0.0.1:8081"
	s.server.Handler.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("status = %d, want 200 even when disabled", w.Code)
	}
	var got sysCaptureState
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Enabled {
		t.Fatal("Enabled must be false when Deps.SysCapture is nil")
	}
}

func TestSysCaptureSettingsUnavailableWhenNil(t *testing.T) {
	s := New("127.0.0.1:0", Deps{Store: fakeStore{}}, slog.New(slog.DiscardHandler))
	w := httptest.NewRecorder()
	r := httptest.NewRequest("PUT", "/api/syscapture/settings", bytes.NewReader([]byte(`{"up":true}`)))
	r.Host = "127.0.0.1:8081"
	r.Header.Set("X-Requested-With", "proxyscope")
	s.server.Handler.ServeHTTP(w, r)
	if w.Code != 404 {
		t.Fatalf("status = %d, want 404", w.Code)
	}
}

func TestSysCaptureStateAndSettingsRoundTrip(t *testing.T) {
	fc := &fakeSysCapture{filter: "tcp.DstPort == 9100", elevated: true, pending: map[int64]*model.RelayPending{}}
	s := New("127.0.0.1:0", Deps{Store: fakeStore{}, SysCapture: fc}, slog.New(slog.DiscardHandler))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/syscapture", nil)
	r.Host = "127.0.0.1:8081"
	s.server.Handler.ServeHTTP(w, r)
	var st sysCaptureState
	json.Unmarshal(w.Body.Bytes(), &st)
	if !st.Enabled || st.Filter != "tcp.DstPort == 9100" || !st.Elevated {
		t.Fatalf("state = %+v", st)
	}

	w = httptest.NewRecorder()
	r = httptest.NewRequest("PUT", "/api/syscapture/settings", bytes.NewReader([]byte(`{"up":true,"down":true}`)))
	r.Host = "127.0.0.1:8081"
	r.Header.Set("X-Requested-With", "proxyscope")
	s.server.Handler.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("settings PUT status = %d", w.Code)
	}
	if !fc.settings.Up || !fc.settings.Down {
		t.Fatalf("settings not applied: %+v", fc.settings)
	}
}

func TestSysCapturePendingForwardAndDrop(t *testing.T) {
	fc := &fakeSysCapture{pending: map[int64]*model.RelayPending{
		1: {RelayPendingSummary: model.RelayPendingSummary{ID: 1, Target: "f", SessionID: 9, Direction: model.RelayUp, Size: 2}, Chunk: &model.Chunk{Data: []byte("hi")}},
	}}
	s := New("127.0.0.1:0", Deps{Store: fakeStore{}, SysCapture: fc}, slog.New(slog.DiscardHandler))

	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/api/syscapture/pending/1", nil)
	r.Host = "127.0.0.1:8081"
	s.server.Handler.ServeHTTP(w, r)
	if w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte(hex.EncodeToString([]byte("hi")))) {
		t.Fatalf("get pending = %d %s", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	r = httptest.NewRequest("POST", "/api/syscapture/pending/1/drop", nil)
	r.Host = "127.0.0.1:8081"
	r.Header.Set("X-Requested-With", "proxyscope")
	s.server.Handler.ServeHTTP(w, r)
	if w.Code != 204 {
		t.Fatalf("drop status = %d", w.Code)
	}
	if _, ok := fc.pending[1]; ok {
		t.Fatal("dropped item should be gone")
	}

	// Already resolved: 409.
	w = httptest.NewRecorder()
	r = httptest.NewRequest("POST", "/api/syscapture/pending/1/drop", nil)
	r.Host = "127.0.0.1:8081"
	r.Header.Set("X-Requested-With", "proxyscope")
	s.server.Handler.ServeHTTP(w, r)
	if w.Code != 409 {
		t.Fatalf("re-drop status = %d, want 409", w.Code)
	}
}

// TestSysCaptureForwardSurfacesTCPLengthMismatchAs400 verifies the
// dedicated rejection path required for TCP system-capture edits: a
// length-changing edit must come back as a specific 400 (not the generic
// 409 "already resolved" a stale id would get), and the item must remain
// held so the client can retry.
func TestSysCaptureForwardSurfacesTCPLengthMismatchAs400(t *testing.T) {
	fc := &fakeSysCapture{
		pending: map[int64]*model.RelayPending{
			1: {RelayPendingSummary: model.RelayPendingSummary{ID: 1, Target: "f", Direction: model.RelayUp}, Chunk: &model.Chunk{Data: []byte("orig")}},
		},
		resolveFn: func(id int64, res model.RelayResolution) error {
			if res.Chunk != nil && len(res.Chunk.Data) != 4 {
				return sysCapture.ErrTCPPayloadLengthMismatch
			}
			return nil
		},
	}
	s := New("127.0.0.1:0", Deps{Store: fakeStore{}, SysCapture: fc}, slog.New(slog.DiscardHandler))

	w := httptest.NewRecorder()
	body := `{"hex":"` + hex.EncodeToString([]byte("short")) + `"}`
	r := httptest.NewRequest("POST", "/api/syscapture/pending/1/forward", bytes.NewReader([]byte(body)))
	r.Host = "127.0.0.1:8081"
	r.Header.Set("X-Requested-With", "proxyscope")
	s.server.Handler.ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("TCP payload length must match")) {
		t.Fatalf("body = %q, want the specific TCP length-mismatch message", w.Body.String())
	}
	if _, ok := fc.pending[1]; !ok {
		t.Fatal("item must remain held after a rejected edit")
	}

	// Not just any error: a genuinely stale id still gets 409, not 400.
	fc.resolveFn = func(int64, model.RelayResolution) error { return model.ErrPendingGone }
	w = httptest.NewRecorder()
	r = httptest.NewRequest("POST", "/api/syscapture/pending/1/forward", bytes.NewReader([]byte(`{}`)))
	r.Host = "127.0.0.1:8081"
	r.Header.Set("X-Requested-With", "proxyscope")
	s.server.Handler.ServeHTTP(w, r)
	if w.Code != 409 {
		t.Fatalf("status = %d, want 409 for a stale id", w.Code)
	}
}
