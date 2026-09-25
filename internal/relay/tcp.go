package relay

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"proxyscope/internal/model"
)

// serveTCP accepts connections for t until ln is closed (by Shutdown),
// which it reports as a clean (nil) return, matching the
// !errors.Is(err, http.ErrServerClosed) convention used elsewhere.
func (s *Service) serveTCP(t Target, ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if isCleanClose(err) {
				return nil
			}
			return err
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleTCPConn(t, conn)
		}()
	}
}

// handleTCPConn dials t.Upstream and relays bytes both ways until either
// side closes or errors, capturing (and, if enabled, holding) every chunk.
func (s *Service) handleTCPConn(t Target, client net.Conn) {
	defer client.Close()

	dialer := &net.Dialer{Timeout: s.cfg.DialTimeout}
	upstream, err := dialer.Dial("tcp", t.Upstream)
	sess := &model.RelaySession{
		Target: t.Name, Protocol: model.RelayTCP,
		ClientAddr: client.RemoteAddr().String(), UpstreamAddr: t.Upstream, OpenedAt: time.Now(),
	}
	if err != nil {
		sess.ClosedAt = time.Now()
		sess.Error = "connecting to upstream: " + err.Error()
		s.saveSession(sess)
		s.log.Warn("relay upstream dial failed", "target", t.Name, "upstream", t.Upstream, "err", err)
		return
	}
	defer upstream.Close()
	s.saveSession(sess)
	s.log.Info("relay session opened", "target", t.Name, "client", sess.ClientAddr, "session", sess.ID)

	// Both directions share one sequence counter (for a true chronological
	// view) and run concurrently, so it must be atomic.
	var seq atomic.Int64
	var upBytes, downBytes int64
	var upErr, downErr error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		upBytes, upErr = s.pump(s.ctx, t.Name, sess.ID, model.RelayUp, client, upstream, &seq)
		upstream.Close() // unblock the other pump if it's blocked reading upstream
	}()
	go func() {
		defer wg.Done()
		downBytes, downErr = s.pump(s.ctx, t.Name, sess.ID, model.RelayDown, upstream, client, &seq)
		client.Close() // unblock the other pump if it's blocked reading the client
	}()
	wg.Wait()

	errStr := ""
	switch {
	case upErr != nil:
		errStr = "client side: " + upErr.Error()
	case downErr != nil:
		errStr = "upstream side: " + downErr.Error()
	}
	s.closeSession(sess.ID, upBytes, downBytes, errStr)
	s.log.Info("relay session closed", "target", t.Name, "session", sess.ID, "bytesUp", upBytes, "bytesDown", downBytes)
}

// pump copies src to dst, capturing (and possibly holding) every chunk. It
// returns the real number of bytes read from src, and any non-clean error.
func (s *Service) pump(ctx context.Context, target string, sessionID int64, dir model.RelayDirection, src, dst net.Conn, seq *atomic.Int64) (int64, error) {
	buf := make([]byte, relayBufSize)
	var total, captured int64
	capReached := false
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			total += int64(n)
			chunk := &model.Chunk{Data: append([]byte(nil), buf[:n]...)}
			oc := s.hold.Hold(ctx, target, sessionID, dir, chunk)
			if !capReached {
				capReached = s.storeChunk(target, sessionID, dir, seq, chunk.Data, oc.Edited, &captured)
			}
			if oc.Verdict != model.VerdictDrop {
				if _, werr := dst.Write(chunk.Data); werr != nil {
					return total, werr
				}
			}
		}
		if rerr != nil {
			if isCleanClose(rerr) {
				return total, nil
			}
			return total, rerr
		}
	}
}
