package ui

import (
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"time"

	"proxyscope/internal/model"
	"proxyscope/internal/sysCapture"
)

// sysCaptureUnavailable is the message every /api/syscapture handler
// returns when Deps.SysCapture is nil (i.e. -syscapture was not enabled at
// startup): a clear, actionable 404 rather than a panic on a nil interface.
const sysCaptureUnavailable = "system-level capture is not enabled (see -syscapture and -syscapture-filter in the README)"

// --- status + live hold queue ---

type sysCaptureState struct {
	Enabled        bool                        `json:"enabled"`
	Filter         string                      `json:"filter,omitempty"`
	Elevated       bool                        `json:"elevated,omitempty"`
	TimeoutSeconds float64                     `json:"timeoutSeconds,omitempty"`
	Settings       model.RelaySettings         `json:"settings"`
	Pending        []model.RelayPendingSummary `json:"pending,omitempty"`
	Now            time.Time                   `json:"now"` // server clock, for countdowns
}

func (s *Server) handleSysCaptureState(w http.ResponseWriter, r *http.Request) {
	if s.sysCapture == nil {
		writeJSON(w, sysCaptureState{Enabled: false, Now: time.Now()})
		return
	}
	writeJSON(w, sysCaptureState{
		Enabled: true, Filter: s.sysCapture.Filter(), Elevated: s.sysCapture.Elevated(),
		TimeoutSeconds: s.sysCapture.Timeout().Seconds(), Settings: s.sysCapture.Settings(),
		Pending: s.sysCapture.List(), Now: time.Now(),
	})
}

func (s *Server) handleSysCaptureSettings(w http.ResponseWriter, r *http.Request) {
	if s.sysCapture == nil {
		http.Error(w, sysCaptureUnavailable, http.StatusNotFound)
		return
	}
	var set model.RelaySettings
	if !readJSON(w, r, &set) {
		return
	}
	s.sysCapture.SetSettings(set)
	writeJSON(w, s.sysCapture.Settings())
}

// --- held packet payload (manual intercept), the byte-stream analog of
// /api/intercept and /api/relay/pending; same hex encoding as relay.go's
// relayPendingView (see its doc comment). ---

func (s *Server) handleSysCapturePendingGet(w http.ResponseWriter, r *http.Request) {
	p, ok := s.sysCapturePending(w, r)
	if !ok {
		return
	}
	writeJSON(w, relayPendingView{RelayPendingSummary: p.RelayPendingSummary, Hex: hex.EncodeToString(p.Chunk.Data)})
}

func (s *Server) handleSysCaptureForward(w http.ResponseWriter, r *http.Request) {
	p, ok := s.sysCapturePending(w, r)
	if !ok {
		return
	}
	var res model.RelayResolution
	if r.ContentLength != 0 {
		var in relayEditPayload
		if !readJSON(w, r, &in) {
			return
		}
		data, err := parseHexEdit(in.Hex)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		res.Chunk = &model.Chunk{Data: data}
	}
	s.resolveSysCapture(w, p.ID, res)
}

func (s *Server) handleSysCaptureDrop(w http.ResponseWriter, r *http.Request) {
	p, ok := s.sysCapturePending(w, r)
	if !ok {
		return
	}
	s.resolveSysCapture(w, p.ID, model.RelayResolution{Drop: true})
}

// resolveSysCapture translates sysCapture.Resolve's errors to HTTP status:
// a stale/already-resolved id is a 409 (matching relay/intercept), but a
// TCP same-length-edit violation is its own explicit 400 naming the
// constraint (see sysCapture.ErrTCPPayloadLengthMismatch's doc comment) --
// never folded into a generic "invalid" message, and the item stays held
// either way so the user can retry.
func (s *Server) resolveSysCapture(w http.ResponseWriter, id int64, res model.RelayResolution) {
	err := s.sysCapture.Resolve(id, res)
	switch {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, sysCapture.ErrTCPPayloadLengthMismatch):
		http.Error(w, err.Error(), http.StatusBadRequest)
	default:
		http.Error(w, err.Error(), http.StatusConflict)
	}
}

func (s *Server) sysCapturePending(w http.ResponseWriter, r *http.Request) (*model.RelayPending, bool) {
	if s.sysCapture == nil {
		http.Error(w, sysCaptureUnavailable, http.StatusNotFound)
		return nil, false
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return nil, false
	}
	p, err := s.sysCapture.Get(id)
	if errors.Is(err, model.ErrPendingGone) {
		http.Error(w, err.Error(), http.StatusConflict)
		return nil, false
	}
	if err != nil {
		s.fail(w, err)
		return nil, false
	}
	return p, true
}

// --- session history (recorded, read from Store; same table pair as the
// relay's, filtered to model.RelaySourceSysCapture, see model.RelaySession) ---

func (s *Server) handleSysCaptureSessions(w http.ResponseWriter, r *http.Request) {
	limit := defaultRelaySessionLimit
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 {
		limit = v
	}
	rows, err := s.store.ListRelaySessions(r.Context(), model.RelaySourceSysCapture, "", limit)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, rows)
}

func (s *Server) handleSysCaptureSessionDetail(w http.ResponseWriter, r *http.Request) {
	s.sessionDetail(w, r, model.RelaySourceSysCapture)
}

// parseHexEdit and relayEditPayload/relayPendingView (internal/ui/relay.go)
// are reused as-is rather than duplicated: a held packet payload's hex
// editing is identical to a held relay chunk's.
