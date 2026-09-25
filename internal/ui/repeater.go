package ui

import (
	"errors"
	"net/http"
	"strconv"

	"proxyscope/internal/model"
)

// repeaterSeed is a stored request prepared for the repeater's edit form.
type repeaterSeed struct {
	SourceID int64  `json:"sourceId"`
	Method   string `json:"method"`
	URL      string `json:"url"`
	Headers  string `json:"headers"`
	// Body.Editable false means binary/oversized: the stored bytes are resent
	// unchanged. BodyTruncated warns that the stored copy is incomplete.
	Body          bodyView `json:"body"`
	BodyTruncated bool     `json:"bodyTruncated"`
}

// repeaterSend is the request body of POST /api/repeater/send.
type repeaterSend struct {
	SourceID int64 `json:"sourceId"` // exchange the tab was created from (for unchanged bodies), 0 if none
	requestEdit
}

// handleRepeaterSeed returns an editable copy of a stored request.
func (s *Server) handleRepeaterSeed(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	ex, err := s.store.Get(r.Context(), id)
	if errors.Is(err, model.ErrNotFound) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	req := exchangeRequest(ex)
	v := newRequestEditView(req)
	seed := repeaterSeed{SourceID: ex.ID, Method: v.Method, URL: v.URL, Headers: v.Headers, Body: v.Body, BodyTruncated: ex.ReqBodyTruncated()}
	if seed.BodyTruncated {
		seed.Body.Editable = false // never edit (and thereby silently resend) a partial body
	}
	writeJSON(w, seed)
}

// handleRepeaterSend validates the edit form, sends it directly (no proxy, no
// intercept) and returns the stored result in the same shape as history detail.
func (s *Server) handleRepeaterSend(w http.ResponseWriter, r *http.Request) {
	var in repeaterSend
	if !readJSON(w, r, &in) {
		return
	}
	orig := &model.Request{}
	if in.SourceID != 0 {
		ex, err := s.store.Get(r.Context(), in.SourceID)
		switch {
		case errors.Is(err, model.ErrNotFound):
			// The original was deleted (history cleared): only a new body can be used.
		case err != nil:
			s.fail(w, err)
			return
		default:
			orig = exchangeRequest(ex)
		}
	}
	req, err := buildRequest(orig, &in.requestEdit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ex, err := s.rep.Send(r.Context(), req)
	if errors.Is(err, model.ErrInvalidRequest) {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, buildDetail(ex))
}
