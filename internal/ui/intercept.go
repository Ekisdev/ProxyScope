package ui

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"proxyscope/internal/model"
)

const maxAPIBody = 64 << 20 // edit forms carry whole bodies

// interceptState is what the UI polls: toggles plus the list of held items.
type interceptState struct {
	Settings       model.InterceptSettings `json:"settings"`
	TimeoutSeconds float64                 `json:"timeoutSeconds"` // 0 = none
	Pending        []model.PendingSummary  `json:"pending"`
	Now            time.Time               `json:"now"` // server clock, for countdowns
}

// pendingView is one held item with edit forms.
type pendingView struct {
	model.PendingSummary
	Request  requestEditView   `json:"request"`
	Response *responseEditView `json:"response,omitempty"`
}

// resolvePayload is the body of a forward action. Empty/absent fields mean
// "forward as-is"; an edit form applies only to the matching item kind.
type resolvePayload struct {
	Request  *requestEdit  `json:"request"`
	Response *responseEdit `json:"response"`
}

func (s *Server) handleInterceptState(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, interceptState{
		Settings:       s.icpt.Settings(),
		TimeoutSeconds: s.icpt.Timeout().Seconds(),
		Pending:        s.icpt.List(),
		Now:            time.Now(),
	})
}

func (s *Server) handleInterceptSettings(w http.ResponseWriter, r *http.Request) {
	var set model.InterceptSettings
	if !readJSON(w, r, &set) {
		return
	}
	s.icpt.SetSettings(set)
	writeJSON(w, s.icpt.Settings())
}

func (s *Server) handleInterceptGet(w http.ResponseWriter, r *http.Request) {
	p, ok := s.pending(w, r)
	if !ok {
		return
	}
	v := pendingView{PendingSummary: p.PendingSummary, Request: newRequestEditView(p.Request), Response: newResponseEditView(p.Response)}
	writeJSON(w, v)
}

func (s *Server) handleInterceptForward(w http.ResponseWriter, r *http.Request) {
	p, ok := s.pending(w, r)
	if !ok {
		return
	}
	var in resolvePayload
	if r.ContentLength != 0 && !readJSON(w, r, &in) {
		return
	}
	var res model.Resolution
	var err error
	switch {
	case p.Kind == model.PendingRequest && in.Request != nil:
		res.Request, err = buildRequest(p.Request, in.Request)
	case p.Kind == model.PendingResponse && in.Response != nil:
		res.Response, err = buildResponse(p.Response, in.Response)
	}
	if err != nil {
		// Invalid edit: report it and keep the item held so nothing is lost.
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.resolve(w, p.ID, res)
}

func (s *Server) handleInterceptDrop(w http.ResponseWriter, r *http.Request) {
	p, ok := s.pending(w, r)
	if !ok {
		return
	}
	s.resolve(w, p.ID, model.Resolution{Drop: true})
}

func (s *Server) resolve(w http.ResponseWriter, id int64, res model.Resolution) {
	if err := s.icpt.Resolve(id, res); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// pending loads the {id} item, answering 400/409 itself on failure.
func (s *Server) pending(w http.ResponseWriter, r *http.Request) (*model.Pending, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return nil, false
	}
	p, err := s.icpt.Get(id)
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

// readJSON decodes a size-limited JSON body into v, answering 400 on failure.
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	body := http.MaxBytesReader(w, r.Body, maxAPIBody)
	dec := json.NewDecoder(body)
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return false
	}
	return true
}
