// Package ui serves the local web UI and its JSON API.
//
// The UI polls GET /api/exchanges?after=<id> for new rows; there is no
// WebSocket by design (simplicity first).
package ui

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"proxyscope/internal/model"
)

//go:embed web
var webFS embed.FS

// Store is the read side of the storage layer needed by the UI.
type Store interface {
	List(ctx context.Context, afterID int64, limit int) ([]model.Summary, error)
	Get(ctx context.Context, id int64) (*model.Exchange, error)
	Clear(ctx context.Context) error

	// Relay (Phase 5) session/chunk reads. target "" means every target.
	ListRelaySessions(ctx context.Context, target string, limit int) ([]model.RelaySessionSummary, error)
	GetRelaySession(ctx context.Context, id int64) (*model.RelaySession, error)
	ListRelayChunks(ctx context.Context, sessionID int64) ([]model.RelayChunk, error)
}

// Interceptor is the live-intercept queue (implemented by intercept.Manager).
type Interceptor interface {
	Settings() model.InterceptSettings
	SetSettings(model.InterceptSettings)
	Timeout() time.Duration
	List() []model.PendingSummary
	Get(id int64) (*model.Pending, error)
	Resolve(id int64, res model.Resolution) error
}

// Repeater sends a request directly and stores the result (implemented by
// repeater.Service).
type Repeater interface {
	Send(ctx context.Context, req *model.Request) (*model.Exchange, error)
}

// Rules is the match & replace rules engine (implemented by rules.Engine).
// Every write validates before touching the file or the active rule set: on
// error nothing changes, so a bad edit never loses previously working rules.
type Rules interface {
	Path() string
	Rules() []model.Rule
	ReadRaw() (string, error)
	SaveRules(rules []model.Rule) error
	SaveRaw(yamlText string) error
	Load() error // re-read the file from disk (manual reload after a hand-edit)
}

// RelayStatus is the generic TCP/UDP relay's configured targets and live
// hold queue (implemented by relay.Service). Session/chunk history is read
// through Store instead, exactly like intercept's held items vs. exchange
// history are two different things (live vs. recorded).
type RelayStatus interface {
	Targets() []model.RelayTarget
	Timeout() time.Duration // shared auto-forward timeout for every target's held chunks
	Settings(target string) model.RelaySettings
	SetSettings(target string, s model.RelaySettings)
	List() []model.RelayPendingSummary
	Get(id int64) (*model.RelayPending, error)
	Resolve(id int64, res model.RelayResolution) error
}

// Deps are the collaborators of the UI server.
type Deps struct {
	Store       Store
	Interceptor Interceptor
	Repeater    Repeater
	Rules       Rules
	Relay       RelayStatus
	CAPEM       []byte // public CA certificate served at /ca.crt (nil disables it)
}

const (
	defaultLimit = 500
	maxLimit     = 1000
)

// Server is the web UI HTTP server.
type Server struct {
	addr   string
	store  Store
	icpt   Interceptor
	rep    Repeater
	rules  Rules
	relay  RelayStatus
	caPEM  []byte // public CA certificate offered for download (never the key)
	log    *slog.Logger
	server *http.Server
}

// New creates the UI server. It does not start listening.
func New(addr string, d Deps, log *slog.Logger) *Server {
	s := &Server{addr: addr, store: d.Store, icpt: d.Interceptor, rep: d.Repeater, rules: d.Rules, relay: d.Relay, caPEM: d.CAPEM, log: log}
	web, err := fs.Sub(webFS, "web")
	if err != nil {
		panic(err) // embedded path is fixed at compile time
	}
	mux := http.NewServeMux()
	mux.Handle("GET /", http.FileServerFS(web))
	mux.HandleFunc("GET /ca.crt", s.handleCA)
	mux.HandleFunc("GET /api/exchanges", s.handleList)
	mux.HandleFunc("GET /api/exchanges/{id}", s.handleGet)
	mux.HandleFunc("DELETE /api/exchanges", s.handleClear)
	mux.HandleFunc("GET /api/exchanges/{id}/repeater", s.handleRepeaterSeed)
	mux.HandleFunc("POST /api/repeater/send", s.handleRepeaterSend)
	mux.HandleFunc("GET /api/intercept", s.handleInterceptState)
	mux.HandleFunc("PUT /api/intercept/settings", s.handleInterceptSettings)
	mux.HandleFunc("GET /api/intercept/{id}", s.handleInterceptGet)
	mux.HandleFunc("POST /api/intercept/{id}/forward", s.handleInterceptForward)
	mux.HandleFunc("POST /api/intercept/{id}/drop", s.handleInterceptDrop)
	mux.HandleFunc("GET /api/rules", s.handleRulesState)
	mux.HandleFunc("PUT /api/rules", s.handleRulesSave)
	mux.HandleFunc("PUT /api/rules/raw", s.handleRulesSaveRaw)
	mux.HandleFunc("POST /api/rules/reload", s.handleRulesReload)
	mux.HandleFunc("GET /api/relay", s.handleRelayState)
	mux.HandleFunc("PUT /api/relay/targets/{name}/settings", s.handleRelaySettings)
	mux.HandleFunc("GET /api/relay/sessions", s.handleRelaySessions)
	mux.HandleFunc("GET /api/relay/sessions/{id}", s.handleRelaySessionDetail)
	mux.HandleFunc("GET /api/relay/pending/{id}", s.handleRelayPendingGet)
	mux.HandleFunc("POST /api/relay/pending/{id}/forward", s.handleRelayForward)
	mux.HandleFunc("POST /api/relay/pending/{id}/drop", s.handleRelayDrop)
	s.server = &http.Server{
		Handler:           s.guard(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}
	return s
}

// ListenAndServe serves until Shutdown; it returns nil after a clean shutdown.
func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.addr, err)
	}
	s.log.Info("web UI listening", "url", "http://"+ln.Addr().String())
	if err := s.server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Shutdown gracefully stops the UI server.
func (s *Server) Shutdown(ctx context.Context) error { return s.server.Shutdown(ctx) }

// guard protects a loopback-bound UI from DNS-rebinding and cross-site abuse:
// the history contains sensitive traffic, so requests whose Host is not a
// loopback name, and cross-site state changes, are rejected. When the UI is
// deliberately bound to a non-loopback address the Host check is skipped.
func (s *Server) guard(next http.Handler) http.Handler {
	checkHost := isLoopbackAddr(s.addr)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if checkHost && !isLoopbackHost(r.Host) {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodGet && r.Header.Get("X-Requested-With") != "proxyscope" {
			http.Error(w, "missing X-Requested-With header", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// handleCA serves the public root CA certificate for installation in a trust store.
func (s *Server) handleCA(w http.ResponseWriter, r *http.Request) {
	if s.caPEM == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", `attachment; filename="proxyscope-ca.crt"`)
	_, _ = w.Write(s.caPEM)
}

func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	limit := defaultLimit
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 {
		limit = min(v, maxLimit)
	}
	rows, err := s.store.List(r.Context(), max(after, 0), limit)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, rows)
}

func (s *Server) handleGet(w http.ResponseWriter, r *http.Request) {
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
	writeJSON(w, buildDetail(ex))
}

func (s *Server) handleClear(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Clear(r.Context()); err != nil {
		s.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	s.log.Error("ui request failed", "err", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}

// isLoopbackAddr reports whether a listen address binds to loopback only.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	return isLoopbackName(host)
}

// isLoopbackHost reports whether an HTTP Host header names loopback.
func isLoopbackHost(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	return isLoopbackName(strings.Trim(host, "[]"))
}

func isLoopbackName(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// --- detail view ---

type headerKV struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type requestView struct {
	Method  string     `json:"method"`
	Path    string     `json:"path"`
	Proto   string     `json:"proto"`
	Host    string     `json:"host"`
	Headers []headerKV `json:"headers"`
	Body    bodyView   `json:"body"`
}

type responseView struct {
	Status     int        `json:"status"`
	StatusText string     `json:"statusText"`
	Headers    []headerKV `json:"headers"`
	Body       bodyView   `json:"body"`
}

type detailView struct {
	ID           int64         `json:"id"`
	Source       string        `json:"source"`
	ReqEdited    bool          `json:"reqEdited,omitempty"`
	RespEdited   bool          `json:"respEdited,omitempty"`
	RulesApplied []string      `json:"rulesApplied,omitempty"`
	Note         string        `json:"note,omitempty"`
	Timestamp    time.Time     `json:"timestamp"`
	DurationMs   float64       `json:"durationMs"`
	URL          string        `json:"url"`
	Error        string        `json:"error,omitempty"`
	Request      requestView   `json:"request"`
	Response     *responseView `json:"response,omitempty"`
}

func buildDetail(ex *model.Exchange) detailView {
	d := detailView{
		ID:           ex.ID,
		Source:       sourceOf(ex),
		ReqEdited:    ex.ReqEdited,
		RespEdited:   ex.RespEdited,
		RulesApplied: ex.RulesApplied,
		Note:         ex.Note,
		Timestamp:    ex.Timestamp,
		DurationMs:   float64(ex.Duration) / float64(time.Millisecond),
		URL:          ex.URL,
		Error:        ex.Error,
		Request: requestView{
			Method:  ex.Method,
			Path:    ex.Path,
			Proto:   ex.Proto,
			Host:    ex.Host,
			Headers: headerList(ex.ReqHeaders),
			Body:    renderBody(ex.ReqHeaders, ex.ReqBody, ex.ReqBodySize),
		},
	}
	if ex.StatusCode != 0 {
		d.Response = &responseView{
			Status:     ex.StatusCode,
			StatusText: http.StatusText(ex.StatusCode),
			Headers:    headerList(ex.RespHeaders),
			Body:       renderBody(ex.RespHeaders, ex.RespBody, ex.RespBodySize),
		}
	}
	return d
}

// headerList flattens a header map into a deterministic, name-sorted list.
func headerList(h http.Header) []headerKV {
	out := make([]headerKV, 0, len(h))
	for name, vals := range h {
		for _, v := range vals {
			out = append(out, headerKV{Name: name, Value: v})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func sourceOf(ex *model.Exchange) string {
	if ex.Source == "" {
		return model.SourceProxy
	}
	return ex.Source
}
