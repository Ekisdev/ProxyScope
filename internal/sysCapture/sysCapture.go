// Package sysCapture implements Phase 6's system-level packet capture: it
// intercepts traffic at the OS network-stack level via WinDivert on
// Windows, so it can see and redirect traffic from a process that has no
// proxy/relay setting and was never pointed at ProxyScope -- including
// kernel-mode components -- as long as that traffic goes through the
// normal Windows network stack. It shares no code path with internal/proxy
// or internal/relay (same independence rule that already separates those
// two from each other, see CLAUDE.md): the network layer is raw IP
// packets, not HTTP messages or a relay's own accepted connections, and
// this package is responsible for re-injecting every packet it diverts
// (forward unmodified, forward edited, or drop), since intercepting at
// this layer means the OS is no longer delivering it on its own.
//
// This is a materially more invasive capability than the proxy or the
// relay: those only see traffic explicitly pointed at ProxyScope, on
// loopback by default. sysCapture, once enabled, can intercept and modify
// traffic from ANY process on the system matching -syscapture-filter, not
// just traffic that chose to go through ProxyScope -- see the README's
// "System-level capture" section, and the security warning that lives
// right next to it, before enabling -syscapture.
//
// Platform status: fully implemented on Windows (capture_windows.go,
// windivert_windows.go), a compiling stub on Linux (capture_linux.go) that
// returns a clear "not implemented" error at runtime and never panics --
// WinDivert has no Linux equivalent (NFQUEUE is a structurally different
// API requiring netfilter/iptables/nftables rules to redirect traffic into
// a queue before ProxyScope ever sees anything), so Linux/NFQUEUE support
// is deferred, consistent with the rest of this project's Arch-verification
// pause. Both files define the same exported Service methods so the rest
// of the program (main.go, internal/ui) never branches on OS.
package sysCapture

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"proxyscope/internal/model"
)

// Config holds sysCapture engine settings.
type Config struct {
	Filter           string        // WinDivert filter expression (network layer); see README for what's filterable
	MaxCapture       int64         // max bytes stored per session per direction; always fully re-injected regardless
	IdleTimeout      time.Duration // evict a session after this much inactivity
	InterceptTimeout time.Duration // auto-forward a held packet's payload after this long (0 = none); shares -intercept-timeout
}

// Sink receives session/chunk events. store.Store implements it, the same
// way it implements relay.Sink -- see model.RelaySession's Source field for
// how the two engines share relay_sessions/relay_chunks without a third
// parallel schema. Declared separately from relay.Sink (rather than
// imported) to keep sysCapture a leaf package independent of internal/relay,
// exactly like relay.Sink is declared independently of proxy.Sink.
type Sink interface {
	// OpenSession inserts s (Source = model.RelaySourceSysCapture) and sets s.ID.
	OpenSession(ctx context.Context, s *model.RelaySession) error
	// CloseSession records a session as finished.
	CloseSession(ctx context.Context, id int64, closedAt time.Time, bytesUp, bytesDown int64, errStr string) error
	// SaveChunk inserts c and sets c.ID.
	SaveChunk(ctx context.Context, c *model.RelayChunk) error
}

// Service runs system-level capture against one configured filter. It
// satisfies ui.SysCaptureStatus through its exported methods, the same
// shape as ui.RelayStatus for the relay.
type Service struct {
	cfg  Config
	sink Sink
	hold *holdQueue
	log  *slog.Logger

	ctx    context.Context
	cancel context.CancelFunc

	mu       sync.Mutex
	sessions map[string]*capSession // by flowKey

	wg sync.WaitGroup

	// divertHandle is the WinDivert handle, set by capture_windows.go's
	// ListenAndServe and read by its Shutdown/Elevated. It is declared here
	// (rather than as an extra field added from a build-tagged file, which
	// Go does not allow) so this struct has one definition shared by both
	// platforms; it is simply never set on Linux, see capture_linux.go.
	divertHandle uintptr
}

// New creates a Service. It does not open the WinDivert handle or start
// capturing; call ListenAndServe for that.
func New(cfg Config, sink Sink, log *slog.Logger) *Service {
	ctx, cancel := context.WithCancel(context.Background())
	return &Service{
		cfg: cfg, sink: sink, hold: newHoldQueue(cfg.InterceptTimeout), log: log,
		ctx: ctx, cancel: cancel,
		sessions: map[string]*capSession{},
	}
}

// Filter returns the configured WinDivert filter expression, for the UI's
// status display.
func (s *Service) Filter() string { return s.cfg.Filter }

// Timeout returns the auto-forward timeout for held packets (0 = none).
func (s *Service) Timeout() time.Duration { return s.cfg.InterceptTimeout }

// Settings returns the current pause-point toggles.
func (s *Service) Settings() model.RelaySettings { return s.hold.Settings() }

// SetSettings changes the pause-point toggles.
func (s *Service) SetSettings(set model.RelaySettings) { s.hold.SetSettings(set) }

// List returns every currently held packet payload.
func (s *Service) List() []model.RelayPendingSummary { return s.hold.List() }

// Get returns one held packet payload with its bytes, or model.ErrPendingGone.
func (s *Service) Get(id int64) (*model.RelayPending, error) { return s.hold.Get(id) }

// Resolve completes a held packet payload (forward as-is/edited, or drop).
// It returns ErrTCPPayloadLengthMismatch (leaving the item held) if an
// edit changed a TCP payload's length -- see packet.go.
func (s *Service) Resolve(id int64, res model.RelayResolution) error { return s.hold.Resolve(id, res) }

// processPacket runs the full capture pipeline on one packet: parse,
// session bookkeeping, manual intercept hold, the TCP length constraint
// (enforced in Resolve, not here), and capture-cap storage. It has no
// WinDivert/syscall dependency, so it is exercised directly by tests with
// synthetic packets, independent of capture_windows.go's real receive loop.
// It returns the bytes to re-inject (identical to pkt when nothing changed
// or the packet could not be parsed -- see packet.go's errUnparseable) and
// whether to drop the packet entirely (never re-inject it).
func (s *Service) processPacket(pkt []byte, outbound bool) (out []byte, drop bool) {
	p, err := parsePacket(pkt)
	if err != nil {
		return pkt, false // forwarded unmodified, not captured (see packet.go)
	}
	dir := model.RelayDown
	if outbound {
		dir = model.RelayUp
	}
	sess := s.sessionFor(p, outbound)
	chunk := &model.Chunk{Data: append([]byte(nil), p.payload(pkt)...)}
	oc := s.hold.Hold(s.ctx, sess.id, dir, p.Protocol, s.cfg.Filter, chunk)

	if oc.Verdict == model.VerdictDrop {
		s.storeChunk(sess, dir, chunk.Data, false)
		s.trackBytes(sess, dir, len(chunk.Data))
		return nil, true
	}
	if !oc.Edited {
		s.storeChunk(sess, dir, chunk.Data, false)
		s.trackBytes(sess, dir, len(chunk.Data))
		return pkt, false
	}
	newPkt, err := replacePayload(pkt, p, chunk.Data)
	if err != nil {
		// Resolve already enforces the TCP length constraint before an edit
		// can reach here, so this should not happen; if it somehow does,
		// forward the original untouched packet rather than send something
		// malformed.
		s.log.Error("syscapture: edited payload rejected after hold, forwarding original", "session", sess.id, "err", err)
		s.storeChunk(sess, dir, p.payload(pkt), false)
		s.trackBytes(sess, dir, p.payloadLen)
		return pkt, false
	}
	s.storeChunk(sess, dir, chunk.Data, true)
	s.trackBytes(sess, dir, len(chunk.Data))
	return newPkt, false
}

func portStr(port uint16) string { return fmt.Sprintf("%d", port) }

// sessionFor returns the session for p's flow, creating and recording one
// (Source = model.RelaySourceSysCapture) if this is the first packet seen
// for it. ClientAddr is this machine's own endpoint (Src for an outbound
// packet, Dst for an inbound one); UpstreamAddr is the remote endpoint --
// there is no fixed client/server role at this layer the way relay has, so
// this is the closest equivalent (see model.RelaySession's doc comment).
func (s *Service) sessionFor(p parsedPacket, outbound bool) *capSession {
	key := flowKey(p)
	s.mu.Lock()
	if sess, ok := s.sessions[key]; ok {
		s.mu.Unlock()
		return sess
	}
	s.mu.Unlock()

	local, remote := net.JoinHostPort(p.DstIP.String(), portStr(p.DstPort)), net.JoinHostPort(p.SrcIP.String(), portStr(p.SrcPort))
	if outbound {
		local, remote = net.JoinHostPort(p.SrcIP.String(), portStr(p.SrcPort)), net.JoinHostPort(p.DstIP.String(), portStr(p.DstPort))
	}
	rec := &model.RelaySession{
		Source: model.RelaySourceSysCapture, Target: s.cfg.Filter, Protocol: p.Protocol,
		ClientAddr: local, UpstreamAddr: remote, OpenedAt: time.Now(),
	}
	s.saveSession(rec)
	cs := &capSession{id: rec.ID, key: key, clientAddr: local, upstreamAddr: remote, protocol: p.Protocol}
	cs.lastActivity.Store(time.Now().UnixNano())

	s.mu.Lock()
	s.sessions[key] = cs
	s.mu.Unlock()
	s.log.Info("syscapture session opened", "session", cs.id, "client", local, "upstream", remote, "protocol", p.Protocol)
	return cs
}

// shutdownCommon cancels the shared context (releasing every held packet
// payload, see holdQueue.wait's ctx.Done() branch), records every session
// still open as closed, and waits for background goroutines (the recv loop
// and the idle sweep, both wg-tracked by the platform file) to finish or
// ctx to expire. Both capture_windows.go and capture_linux.go call this
// from their own Shutdown after doing any platform-specific teardown
// (closing the WinDivert handle, on Windows; nothing, on Linux).
func (s *Service) shutdownCommon(ctx context.Context) error {
	s.cancel()
	s.mu.Lock()
	var open []*capSession
	for key, sess := range s.sessions {
		delete(s.sessions, key)
		open = append(open, sess)
	}
	s.mu.Unlock()
	for _, sess := range open {
		s.closeSession(sess)
	}

	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
