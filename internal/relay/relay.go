// Package relay implements a generic TCP/UDP byte relay (Phase 5),
// independent of the HTTP proxy engine in internal/proxy: it is not built
// on top of proxy.forward and shares no code path with it. Each configured
// Target listens on a local address and forwards raw bytes bidirectionally
// to an upstream address, capturing every chunk (up to a per-session,
// per-direction cap, see storeChunk) and, if enabled for that target and
// direction, pausing it for manual hex edit/drop via the pattern in
// hold.go.
package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"proxyscope/internal/model"
)

// relayBufSize bounds a single Read() from the wire, so it also bounds the
// size of one captured chunk. There is no message framing at this layer
// (unlike HTTP's Content-Length/chunked), so this is the only meaningful
// notion of "one chunk" a generic byte relay has.
const relayBufSize = 32 * 1024

// Target is one configured relay: listen locally, forward to upstream. It
// is an alias for model.RelayTarget (not a new type) so ui can reference
// target info without importing this package, exactly like the match &
// replace rule types alias model.Rule etc.
type Target = model.RelayTarget

// Config holds relay engine settings.
type Config struct {
	Targets []Target

	DialTimeout      time.Duration // dialing the upstream (shares -dial-timeout with the HTTP proxy)
	MaxCapture       int64         // max bytes stored per session per direction; always fully forwarded regardless
	UDPIdleTimeout   time.Duration // evict a UDP session after this much inactivity
	InterceptTimeout time.Duration // auto-forward a held chunk after this long (0 = none); shares -intercept-timeout
}

// Sink receives session/chunk events. store.Store implements it.
type Sink interface {
	// OpenSession inserts s and sets s.ID.
	OpenSession(ctx context.Context, s *model.RelaySession) error
	// CloseSession records a session as finished.
	CloseSession(ctx context.Context, id int64, closedAt time.Time, bytesUp, bytesDown int64, errStr string) error
	// SaveChunk inserts c and sets c.ID.
	SaveChunk(ctx context.Context, c *model.RelayChunk) error
}

// Service runs every configured relay target. It satisfies ui.RelayStatus/
// ui.RelayHold through its exported methods.
type Service struct {
	cfg  Config
	sink Sink
	hold *holdQueue
	log  *slog.Logger

	ctx    context.Context
	cancel context.CancelFunc

	mu        sync.Mutex
	listeners map[string]io.Closer       // target name -> listener/conn, for Shutdown
	boundAddr map[string]string          // target name -> actual bound "host:port" (differs from Target.Listen when it ends in ":0")
	udpState  map[string]*udpTargetState // target name -> live UDP sessions

	wg sync.WaitGroup
}

// New creates a Service. It does not start listening.
func New(cfg Config, sink Sink, log *slog.Logger) *Service {
	ctx, cancel := context.WithCancel(context.Background())
	return &Service{
		cfg: cfg, sink: sink, hold: newHoldQueue(cfg.InterceptTimeout), log: log,
		ctx: ctx, cancel: cancel,
		listeners: map[string]io.Closer{},
		boundAddr: map[string]string{},
		udpState:  map[string]*udpTargetState{},
	}
}

// Targets returns the configured targets, for the UI's status listing.
func (s *Service) Targets() []Target { return s.cfg.Targets }

// Addr returns the actual address target is bound to (useful when its
// configured Listen port is ":0", e.g. in tests), and whether it is
// currently listening at all.
func (s *Service) Addr(target string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.boundAddr[target]
	return a, ok
}

// Timeout returns the auto-forward timeout shared by every target (0 = none).
func (s *Service) Timeout() time.Duration { return s.cfg.InterceptTimeout }

// Settings returns target's current pause-point toggles.
func (s *Service) Settings(target string) model.RelaySettings { return s.hold.Settings(target) }

// SetSettings changes target's pause-point toggles.
func (s *Service) SetSettings(target string, set model.RelaySettings) {
	s.hold.SetSettings(target, set)
}

// List returns every currently held chunk, across all targets.
func (s *Service) List() []model.RelayPendingSummary { return s.hold.List() }

// Get returns one held chunk with its bytes, or model.ErrPendingGone.
func (s *Service) Get(id int64) (*model.RelayPending, error) { return s.hold.Get(id) }

// Resolve completes a held chunk (forward as-is/edited, or drop).
func (s *Service) Resolve(id int64, res model.RelayResolution) error { return s.hold.Resolve(id, res) }

// ListenAndServe starts every configured target and blocks until every
// target's serve loop ends (normally because Shutdown closed its
// listener). It returns the first non-shutdown error, or nil.
func (s *Service) ListenAndServe() error {
	errc := make(chan error, len(s.cfg.Targets))
	for _, t := range s.cfg.Targets {
		switch t.Protocol {
		case model.RelayTCP:
			ln, err := net.Listen("tcp", t.Listen)
			if err != nil {
				return fmt.Errorf("relay %s: listen on %s: %w", t.Name, t.Listen, err)
			}
			s.trackListener(t.Name, ln, ln.Addr().String())
			s.log.Info("relay listening", "target", t.Name, "protocol", "tcp", "addr", ln.Addr().String(), "upstream", t.Upstream)
			s.wg.Add(1)
			go func(t Target, ln net.Listener) { defer s.wg.Done(); errc <- s.serveTCP(t, ln) }(t, ln)
		case model.RelayUDP:
			addr, err := net.ResolveUDPAddr("udp", t.Listen)
			if err != nil {
				return fmt.Errorf("relay %s: resolve %s: %w", t.Name, t.Listen, err)
			}
			conn, err := net.ListenUDP("udp", addr)
			if err != nil {
				return fmt.Errorf("relay %s: listen on %s: %w", t.Name, t.Listen, err)
			}
			s.trackListener(t.Name, conn, conn.LocalAddr().String())
			s.log.Info("relay listening", "target", t.Name, "protocol", "udp", "addr", conn.LocalAddr().String(), "upstream", t.Upstream)
			s.wg.Add(1)
			go func(t Target, conn *net.UDPConn) { defer s.wg.Done(); errc <- s.serveUDP(t, conn) }(t, conn)
		default:
			return fmt.Errorf("relay %s: unknown protocol %q", t.Name, t.Protocol)
		}
	}
	var firstErr error
	for range s.cfg.Targets {
		if err := <-errc; err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Shutdown stops every listener and live session, releases every held
// chunk (via the shutdown context passed to Hold, see hold.go), and waits
// for every goroutine to finish or ctx to expire.
func (s *Service) Shutdown(ctx context.Context) error {
	s.cancel()
	s.mu.Lock()
	for _, l := range s.listeners {
		l.Close()
	}
	for _, state := range s.udpState {
		state.mu.Lock()
		for _, sess := range state.sessions {
			sess.upstreamConn.Close()
		}
		state.mu.Unlock()
	}
	s.mu.Unlock()

	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Service) trackListener(name string, l io.Closer, addr string) {
	s.mu.Lock()
	s.listeners[name] = l
	s.boundAddr[name] = addr
	s.mu.Unlock()
}

// isCleanClose reports whether err is just the wire ending normally (EOF)
// or a listener/connection this process itself closed.
func isCleanClose(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed)
}

// saveSession inserts sess (logging, never failing the caller, matching
// proxy.save's "a failed Sink.Save is logged, never propagated" rule).
func (s *Service) saveSession(sess *model.RelaySession) {
	if err := s.sink.OpenSession(context.Background(), sess); err != nil {
		s.log.Error("relay: saving session failed", "target", sess.Target, "err", err)
	}
}

func (s *Service) closeSession(id int64, bytesUp, bytesDown int64, errStr string) {
	if err := s.sink.CloseSession(context.Background(), id, time.Now(), bytesUp, bytesDown, errStr); err != nil {
		s.log.Error("relay: closing session failed", "session", id, "err", err)
	}
}

// storeChunk persists one captured chunk row, respecting the per-session,
// per-direction capture cap (cfg.MaxCapture): the full stream is always
// forwarded regardless, but once *captured would exceed the cap, only the
// portion that still fits is stored, with a note, and the caller must stop
// calling storeChunk for this (session, direction) afterward — it reports
// that via its bool result, exactly mirroring how proxy.forward truncates a
// body at -max-body while still relaying it in full.
func (s *Service) storeChunk(target string, sessionID int64, dir model.RelayDirection, seq *atomic.Int64, data []byte, edited bool, captured *int64) (capReached bool) {
	stored := data
	note := ""
	if *captured+int64(len(data)) > s.cfg.MaxCapture {
		room := s.cfg.MaxCapture - *captured
		if room < 0 {
			room = 0
		}
		stored = data[:room]
		note = fmt.Sprintf("capture cap reached (%d bytes stored for this direction); further chunks are still relayed but not stored", s.cfg.MaxCapture)
		capReached = true
	}
	c := &model.RelayChunk{
		SessionID: sessionID, Seq: seq.Add(1), Direction: dir, Timestamp: time.Now(),
		Data: stored, DataSize: int64(len(data)), Edited: edited, Note: note,
	}
	*captured += int64(len(stored))
	if err := s.sink.SaveChunk(context.Background(), c); err != nil {
		s.log.Error("relay: saving chunk failed", "target", target, "session", sessionID, "err", err)
	}
	return capReached
}
