package ui

import (
	"net/http"

	"proxyscope/internal/model"
)

// rulesState is what GET /api/rules returns and every successful write
// echoes back: the structured rules (for the list/form view) and the file's
// raw text (for the "edit as raw YAML" view), together so the UI never needs
// a second round trip to keep both in sync.
type rulesState struct {
	Path  string       `json:"path"`
	Rules []model.Rule `json:"rules"`
	Raw   string       `json:"raw"`
}

func (s *Server) rulesStateView() (rulesState, error) {
	raw, err := s.rules.ReadRaw()
	if err != nil {
		return rulesState{}, err
	}
	rs := s.rules.Rules()
	if rs == nil {
		rs = []model.Rule{}
	}
	return rulesState{Path: s.rules.Path(), Rules: rs, Raw: raw}, nil
}

func (s *Server) handleRulesState(w http.ResponseWriter, r *http.Request) {
	st, err := s.rulesStateView()
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, st)
}

// rulesPayload is the body of PUT /api/rules: the full structured rule list,
// which replaces the file's contents (array order = evaluation order).
type rulesPayload struct {
	Rules []model.Rule `json:"rules"`
}

func (s *Server) handleRulesSave(w http.ResponseWriter, r *http.Request) {
	var in rulesPayload
	if !readJSON(w, r, &in) {
		return
	}
	if err := s.rules.SaveRules(in.Rules); err != nil {
		// A validation error leaves the previous rule set active and the
		// file untouched; report it and let the UI keep the user's edits.
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.writeRulesState(w)
}

// rawPayload is the body of PUT /api/rules/raw: the whole file's YAML text,
// written verbatim (so hand-added comments/formatting survive).
type rawPayload struct {
	YAML string `json:"yaml"`
}

func (s *Server) handleRulesSaveRaw(w http.ResponseWriter, r *http.Request) {
	var in rawPayload
	if !readJSON(w, r, &in) {
		return
	}
	if err := s.rules.SaveRaw(in.YAML); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.writeRulesState(w)
}

// handleRulesReload re-reads the rules file from disk: for when it was
// hand-edited outside the UI. A bad file is reported and the previously
// active rules keep running (Engine.Load never blanks out a working set).
func (s *Server) handleRulesReload(w http.ResponseWriter, r *http.Request) {
	if err := s.rules.Load(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.writeRulesState(w)
}

func (s *Server) writeRulesState(w http.ResponseWriter) {
	st, err := s.rulesStateView()
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, st)
}
