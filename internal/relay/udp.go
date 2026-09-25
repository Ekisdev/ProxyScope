package relay

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"proxyscope/internal/model"
)

// sweepInterval picks how often to check for idle UDP sessions, scaled to
// the configured idle timeout so a short timeout (as in tests) is actually
// honored promptly, while a realistic one doesn't poll needlessly often.
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

// udpSession is one "session" for UDP purposes: all datagrams sharing a
// client source address+port (see Config.UDPIdleTimeout). Its own upstream
// socket, dedicated to this client, is what lets return datagrams be routed
// back to the right client (the standard UDP relay/NAT pattern).
type udpSession struct {
	id           int64
	clientAddr   *net.UDPAddr
	upstreamConn net.Conn

	// seq is touched by both the target's single shared inbound-datagram
	// reader (client -> upstream, i.e. "up") and this session's own
	// dedicated downstream reader goroutine (upstream -> client, "down"),
	// so it must be atomic. bytes/lastActivity are read by the idle-sweep
	// goroutine while a pump may still be writing them, so they are atomic
	// too. upCaptured/upCapReached are touched only by the shared inbound
	// reader; downCaptured/downCapReached only by this session's own
	// downstream reader: each pair has exactly one writer goroutine, so
	// plain fields are safe.
	seq          atomic.Int64
	lastActivity atomic.Int64 // UnixNano
	bytesUp      atomic.Int64
	bytesDown    atomic.Int64

	upCaptured     int64
	upCapReached   bool
	downCaptured   int64
	downCapReached bool
}

// udpTargetState is the live session set for one UDP target.
type udpTargetState struct {
	mu       sync.Mutex
	sessions map[string]*udpSession // by client "ip:port"
}

// serveUDP reads datagrams for t until conn is closed (by Shutdown), which
// it reports as a clean (nil) return.
func (s *Service) serveUDP(t Target, conn *net.UDPConn) error {
	state := &udpTargetState{sessions: map[string]*udpSession{}}
	s.mu.Lock()
	s.udpState[t.Name] = state
	s.mu.Unlock()

	go s.sweepUDPLoop(t, state)

	buf := make([]byte, relayBufSize)
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if isCleanClose(err) {
				return nil
			}
			return err
		}
		if n == 0 {
			continue
		}
		sess := s.udpSessionFor(t, conn, addr, state)
		if sess == nil {
			continue // dialing the upstream failed; already logged and recorded
		}
		sess.lastActivity.Store(time.Now().UnixNano())

		chunk := &model.Chunk{Data: append([]byte(nil), buf[:n]...)}
		oc := s.hold.Hold(s.ctx, t.Name, sess.id, model.RelayUp, chunk)
		if !sess.upCapReached {
			sess.upCapReached = s.storeChunk(t.Name, sess.id, model.RelayUp, &sess.seq, chunk.Data, oc.Edited, &sess.upCaptured)
		}
		if oc.Verdict != model.VerdictDrop {
			if _, werr := sess.upstreamConn.Write(chunk.Data); werr != nil {
				s.log.Warn("relay: writing to upstream failed", "target", t.Name, "session", sess.id, "err", werr)
			}
		}
		sess.bytesUp.Add(int64(n))
	}
}

// udpSessionFor returns the existing session for addr, or dials the
// upstream and creates one (spawning its downstream reader).
func (s *Service) udpSessionFor(t Target, listener *net.UDPConn, addr *net.UDPAddr, state *udpTargetState) *udpSession {
	key := addr.String()
	state.mu.Lock()
	if sess, ok := state.sessions[key]; ok {
		state.mu.Unlock()
		return sess
	}
	state.mu.Unlock()

	dialer := &net.Dialer{Timeout: s.cfg.DialTimeout}
	upstream, err := dialer.Dial("udp", t.Upstream)
	sess := &model.RelaySession{
		Target: t.Name, Protocol: model.RelayUDP,
		ClientAddr: key, UpstreamAddr: t.Upstream, OpenedAt: time.Now(),
	}
	if err != nil {
		sess.ClosedAt = time.Now()
		sess.Error = "connecting to upstream: " + err.Error()
		s.saveSession(sess)
		s.log.Warn("relay upstream dial failed", "target", t.Name, "upstream", t.Upstream, "err", err)
		return nil
	}
	s.saveSession(sess)
	s.log.Info("relay session opened", "target", t.Name, "client", key, "session", sess.ID)

	us := &udpSession{id: sess.ID, clientAddr: addr, upstreamConn: upstream}
	us.lastActivity.Store(time.Now().UnixNano())

	state.mu.Lock()
	state.sessions[key] = us
	state.mu.Unlock()

	s.wg.Add(1)
	go func() { defer s.wg.Done(); s.udpDownstreamLoop(t, listener, state, us) }()
	return us
}

// udpDownstreamLoop relays upstream -> client for one UDP session until the
// upstream socket errors or is closed (by idle eviction or Shutdown).
func (s *Service) udpDownstreamLoop(t Target, listener *net.UDPConn, state *udpTargetState, sess *udpSession) {
	buf := make([]byte, relayBufSize)
	for {
		n, rerr := sess.upstreamConn.Read(buf)
		if n > 0 {
			chunk := &model.Chunk{Data: append([]byte(nil), buf[:n]...)}
			oc := s.hold.Hold(s.ctx, t.Name, sess.id, model.RelayDown, chunk)
			if !sess.downCapReached {
				sess.downCapReached = s.storeChunk(t.Name, sess.id, model.RelayDown, &sess.seq, chunk.Data, oc.Edited, &sess.downCaptured)
			}
			if oc.Verdict != model.VerdictDrop {
				if _, werr := listener.WriteToUDP(chunk.Data, sess.clientAddr); werr != nil {
					s.log.Warn("relay: writing to client failed", "target", t.Name, "session", sess.id, "err", werr)
				}
			}
			sess.bytesDown.Add(int64(n))
			sess.lastActivity.Store(time.Now().UnixNano())
		}
		if rerr != nil {
			return
		}
	}
}

func (s *Service) sweepUDPLoop(t Target, state *udpTargetState) {
	ticker := time.NewTicker(sweepInterval(s.cfg.UDPIdleTimeout))
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.sweepIdleUDP(t, state)
		case <-s.ctx.Done():
			return
		}
	}
}

// sweepIdleUDP closes and evicts every session in state idle longer than
// cfg.UDPIdleTimeout: UDP has no FIN/RST, so this is the only way a session
// ever ends short of process shutdown.
func (s *Service) sweepIdleUDP(t Target, state *udpTargetState) {
	cutoff := time.Now().Add(-s.cfg.UDPIdleTimeout).UnixNano()
	state.mu.Lock()
	var evict []*udpSession
	for key, sess := range state.sessions {
		if sess.lastActivity.Load() < cutoff {
			delete(state.sessions, key)
			evict = append(evict, sess)
		}
	}
	state.mu.Unlock()
	for _, sess := range evict {
		sess.upstreamConn.Close() // unblocks udpDownstreamLoop's Read
		s.closeSession(sess.id, sess.bytesUp.Load(), sess.bytesDown.Load(), "")
		s.log.Info("relay UDP session idle, evicted", "target", t.Name, "session", sess.id)
	}
}
