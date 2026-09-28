package sysCapture

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"proxyscope/internal/model"
)

// capSession is one flow-level session for sysCapture purposes: all packets
// sharing a 4-tuple (regardless of direction), grouped by an idle timeout
// the same way relay's UDP sessions are (see internal/relay/udp.go) --
// WinDivert hands over raw packets with no accept()/connection API, so
// there is no TCP-specific "session" event to key off, and this project's
// approved Phase 6 plan deliberately treats TCP the same way as UDP here
// rather than tracking FIN/RST/SYN to end a session early.
type capSession struct {
	id           int64
	key          string
	clientAddr   string // this machine's own endpoint (see Service.sessionFor)
	upstreamAddr string
	protocol     model.RelayProtocol

	// seq/lastActivity/bytesUp/bytesDown are read by the idle-sweep
	// goroutine (session.go's sweepLoop) while the single receive loop
	// goroutine (capture_windows.go) may still be writing them, so they are
	// atomic -- the same reasoning as relay's udpSession fields.
	seq          atomic.Int64
	lastActivity atomic.Int64 // UnixNano
	bytesUp      atomic.Int64
	bytesDown    atomic.Int64

	// upCaptured/upCapReached/downCaptured/downCapReached are touched only
	// by the single receive loop goroutine (there is exactly one WinDivert
	// handle and one blocking Recv call in this design, see hold.go's Hold
	// doc comment), so plain fields are safe.
	upCaptured     int64
	upCapReached   bool
	downCaptured   int64
	downCapReached bool
}

// sweepInterval picks how often to check for idle sessions, scaled to the
// configured idle timeout exactly like relay's udp.go sweepInterval, so a
// short timeout (as in tests) is actually honored promptly.
func sweepInterval(idle time.Duration) time.Duration {
	iv := idle / 4
	if iv < time.Second {
		iv = time.Second
	}
	if iv > 30*time.Second {
		iv = 30 * time.Second
	}
	return iv
}

// sweepLoop periodically evicts idle sessions until ctx is done. Reaping
// idle sessions is ordinary resource-lifecycle housekeeping, not a "worker
// goroutine" in the sense CLAUDE.md's live-intercept rule forbids -- that
// rule is about never letting a held item block on something other than
// its own request/connection, and there is nothing pausable involved here.
func (s *Service) sweepLoop() {
	ticker := time.NewTicker(sweepInterval(s.cfg.IdleTimeout))
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.sweepIdle()
		case <-s.ctx.Done():
			return
		}
	}
}

func (s *Service) sweepIdle() {
	cutoff := time.Now().Add(-s.cfg.IdleTimeout).UnixNano()
	s.mu.Lock()
	var evict []*capSession
	for key, sess := range s.sessions {
		if sess.lastActivity.Load() < cutoff {
			delete(s.sessions, key)
			evict = append(evict, sess)
		}
	}
	s.mu.Unlock()
	for _, sess := range evict {
		s.closeSession(sess)
		s.log.Info("syscapture session idle, evicted", "session", sess.id)
	}
}

// saveSession inserts rec (logging, never failing the caller, matching
// relay.Service.saveSession's "a failed Sink.Save is logged, never
// propagated" rule) and sets rec.ID onto the in-memory session.
func (s *Service) saveSession(rec *model.RelaySession) {
	if err := s.sink.OpenSession(context.Background(), rec); err != nil {
		s.log.Error("syscapture: saving session failed", "target", rec.Target, "err", err)
	}
}

func (s *Service) closeSession(sess *capSession) {
	if err := s.sink.CloseSession(context.Background(), sess.id, time.Now(), sess.bytesUp.Load(), sess.bytesDown.Load(), ""); err != nil {
		s.log.Error("syscapture: closing session failed", "session", sess.id, "err", err)
	}
}

func (s *Service) trackBytes(sess *capSession, dir model.RelayDirection, n int) {
	if dir == model.RelayUp {
		sess.bytesUp.Add(int64(n))
	} else {
		sess.bytesDown.Add(int64(n))
	}
	sess.lastActivity.Store(time.Now().UnixNano())
}

// storeChunk persists one captured packet payload, respecting the
// per-session, per-direction capture cap (cfg.MaxCapture) exactly like
// relay.Service.storeChunk: the full packet is always re-injected
// regardless, but once *captured would exceed the cap, only the portion
// that still fits is stored, with a note, and no further chunk rows are
// stored for that (session, direction) afterward.
func (s *Service) storeChunk(sess *capSession, dir model.RelayDirection, data []byte, edited bool) {
	captured, capReached := &sess.upCaptured, &sess.upCapReached
	if dir == model.RelayDown {
		captured, capReached = &sess.downCaptured, &sess.downCapReached
	}
	if *capReached {
		return
	}
	stored := data
	note := ""
	if *captured+int64(len(data)) > s.cfg.MaxCapture {
		room := s.cfg.MaxCapture - *captured
		if room < 0 {
			room = 0
		}
		stored = data[:room]
		note = fmt.Sprintf("capture cap reached (%d bytes stored for this direction); further packets are still re-injected but not stored", s.cfg.MaxCapture)
		*capReached = true
	}
	c := &model.RelayChunk{
		SessionID: sess.id, Seq: sess.seq.Add(1), Direction: dir, Timestamp: time.Now(),
		Data: stored, DataSize: int64(len(data)), Edited: edited, Note: note,
	}
	*captured += int64(len(stored))
	if err := s.sink.SaveChunk(context.Background(), c); err != nil {
		s.log.Error("syscapture: saving chunk failed", "session", sess.id, "err", err)
	}
}
