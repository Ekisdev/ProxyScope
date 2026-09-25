package ui

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"proxyscope/internal/model"
)

const defaultRelaySessionLimit = 200

// --- target status + live hold queue ---

type relayTargetView struct {
	model.RelayTarget
	Settings model.RelaySettings `json:"settings"`
}

type relayState struct {
	Targets        []relayTargetView           `json:"targets"`
	TimeoutSeconds float64                     `json:"timeoutSeconds"` // 0 = none
	Pending        []model.RelayPendingSummary `json:"pending"`
	Now            time.Time                   `json:"now"` // server clock, for countdowns
}

func (s *Server) handleRelayState(w http.ResponseWriter, r *http.Request) {
	targets := s.relay.Targets()
	views := make([]relayTargetView, len(targets))
	for i, t := range targets {
		views[i] = relayTargetView{RelayTarget: t, Settings: s.relay.Settings(t.Name)}
	}
	writeJSON(w, relayState{
		Targets:        views,
		TimeoutSeconds: s.relay.Timeout().Seconds(),
		Pending:        s.relay.List(),
		Now:            time.Now(),
	})
}

func (s *Server) handleRelaySettings(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var set model.RelaySettings
	if !readJSON(w, r, &set) {
		return
	}
	s.relay.SetSettings(name, set)
	writeJSON(w, s.relay.Settings(name))
}

// --- held chunk (manual intercept), the byte-stream analog of /api/intercept ---

// relayPendingView is a held chunk with an edit form. Hex is a plain,
// continuous hex string (encoding/hex.EncodeToString), meant to be edited
// and decoded back with encoding/hex.DecodeString — a different, simpler
// rendering than the offset/hex/ASCII hexView used for read-only session
// chunk history below, because that format is display-only and not cleanly
// reversible.
type relayPendingView struct {
	model.RelayPendingSummary
	Hex string `json:"hex"`
}

func (s *Server) handleRelayPendingGet(w http.ResponseWriter, r *http.Request) {
	p, ok := s.relayPending(w, r)
	if !ok {
		return
	}
	writeJSON(w, relayPendingView{RelayPendingSummary: p.RelayPendingSummary, Hex: hex.EncodeToString(p.Chunk.Data)})
}

// relayEditPayload is the body of a forward action. An absent/empty Hex
// (with no field at all) means "forward as-is"; distinguishing that from
// "edited to an empty chunk" is why forward's payload is itself optional
// (see handleRelayForward), same as the HTTP intercept endpoints.
type relayEditPayload struct {
	Hex string `json:"hex"`
}

func (s *Server) handleRelayForward(w http.ResponseWriter, r *http.Request) {
	p, ok := s.relayPending(w, r)
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
	s.resolveRelay(w, p.ID, res)
}

func (s *Server) handleRelayDrop(w http.ResponseWriter, r *http.Request) {
	p, ok := s.relayPending(w, r)
	if !ok {
		return
	}
	s.resolveRelay(w, p.ID, model.RelayResolution{Drop: true})
}

func (s *Server) resolveRelay(w http.ResponseWriter, id int64, res model.RelayResolution) {
	if err := s.relay.Resolve(id, res); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) relayPending(w http.ResponseWriter, r *http.Request) (*model.RelayPending, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return nil, false
	}
	p, err := s.relay.Get(id)
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

// parseHexEdit decodes a user-edited hex string, tolerating the whitespace
// a pasted-in "68 65 6c 6c 6f"-style dump would have.
func parseHexEdit(s string) ([]byte, error) {
	s = strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, s)
	data, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid hex: %w", err)
	}
	return data, nil
}

// --- session history (recorded, read from Store) ---

func (s *Server) handleRelaySessions(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	limit := defaultRelaySessionLimit
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 {
		limit = v
	}
	rows, err := s.store.ListRelaySessions(r.Context(), target, limit)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, rows)
}

// relayChunkView is one captured chunk, rendered as a hex dump for
// read-only display (reusing hexView, the same helper renderBody's binary
// HTTP bodies use — see body.go).
type relayChunkView struct {
	ID        int64     `json:"id"`
	Seq       int64     `json:"seq"`
	Direction string    `json:"direction"`
	Timestamp time.Time `json:"timestamp"`
	Size      int64     `json:"size"`   // real size on the wire
	Stored    int       `json:"stored"` // bytes kept in the database
	Truncated bool      `json:"truncated"`
	Edited    bool      `json:"edited"`
	Note      string    `json:"note,omitempty"`
	Hex       string    `json:"hex"`
	Clipped   bool      `json:"clipped,omitempty"`
}

type relaySessionDetailView struct {
	ID           int64            `json:"id"`
	Target       string           `json:"target"`
	Protocol     string           `json:"protocol"`
	ClientAddr   string           `json:"clientAddr"`
	UpstreamAddr string           `json:"upstreamAddr"`
	OpenedAt     time.Time        `json:"openedAt"`
	ClosedAt     *time.Time       `json:"closedAt,omitempty"`
	BytesUp      int64            `json:"bytesUp"`
	BytesDown    int64            `json:"bytesDown"`
	Error        string           `json:"error,omitempty"`
	Chunks       []relayChunkView `json:"chunks"`
}

func (s *Server) handleRelaySessionDetail(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	sess, err := s.store.GetRelaySession(r.Context(), id)
	if errors.Is(err, model.ErrNotFound) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	chunks, err := s.store.ListRelayChunks(r.Context(), id)
	if err != nil {
		s.fail(w, err)
		return
	}
	d := relaySessionDetailView{
		ID: sess.ID, Target: sess.Target, Protocol: string(sess.Protocol),
		ClientAddr: sess.ClientAddr, UpstreamAddr: sess.UpstreamAddr,
		OpenedAt: sess.OpenedAt, BytesUp: sess.BytesUp, BytesDown: sess.BytesDown, Error: sess.Error,
		Chunks: make([]relayChunkView, len(chunks)),
	}
	if !sess.ClosedAt.IsZero() {
		d.ClosedAt = &sess.ClosedAt
	}
	for i, c := range chunks {
		hexContent, clipped := hexView(c.Data)
		d.Chunks[i] = relayChunkView{
			ID: c.ID, Seq: c.Seq, Direction: string(c.Direction), Timestamp: c.Timestamp,
			Size: c.DataSize, Stored: len(c.Data), Truncated: c.DataTruncated(),
			Edited: c.Edited, Note: c.Note, Hex: hexContent, Clipped: clipped,
		}
	}
	writeJSON(w, d)
}
