package relay

import (
	"context"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"proxyscope/internal/model"
)

// fakeSink records everything in memory for assertions.
type fakeSink struct {
	mu          sync.Mutex
	nextSession int64
	nextChunk   int64
	sessions    []*model.RelaySession
	chunks      []*model.RelayChunk
}

func (f *fakeSink) OpenSession(_ context.Context, s *model.RelaySession) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextSession++
	s.ID = f.nextSession
	cp := *s
	f.sessions = append(f.sessions, &cp)
	return nil
}

func (f *fakeSink) CloseSession(_ context.Context, id int64, closedAt time.Time, bytesUp, bytesDown int64, errStr string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range f.sessions {
		if s.ID == id {
			s.ClosedAt, s.BytesUp, s.BytesDown, s.Error = closedAt, bytesUp, bytesDown, errStr
		}
	}
	return nil
}

func (f *fakeSink) SaveChunk(_ context.Context, c *model.RelayChunk) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextChunk++
	c.ID = f.nextChunk
	cp := *c
	cp.Data = append([]byte(nil), c.Data...)
	f.chunks = append(f.chunks, &cp)
	return nil
}

func (f *fakeSink) chunksFor(sessionID int64) []*model.RelayChunk {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*model.RelayChunk
	for _, c := range f.chunks {
		if c.SessionID == sessionID {
			out = append(out, c)
		}
	}
	return out
}

// session returns a COPY of the session (never the pointer stored
// internally), so callers can read it safely without racing CloseSession's
// in-place mutation of the original.
func (f *fakeSink) session(id int64) *model.RelaySession {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, s := range f.sessions {
		if s.ID == id {
			cp := *s
			return &cp
		}
	}
	return nil
}

// firstSession is session() for whichever session was opened first, or nil.
func (f *fakeSink) firstSession() *model.RelaySession {
	f.mu.Lock()
	if len(f.sessions) == 0 {
		f.mu.Unlock()
		return nil
	}
	cp := *f.sessions[0]
	f.mu.Unlock()
	return &cp
}

func testConfig(targets ...Target) Config {
	return Config{
		Targets: targets, DialTimeout: 2 * time.Second, MaxCapture: 1 << 20,
		UDPIdleTimeout: time.Minute, InterceptTimeout: 10 * time.Second,
	}
}

func startService(t *testing.T, cfg Config, sink *fakeSink) *Service {
	t.Helper()
	svc := New(cfg, sink, slog.New(slog.DiscardHandler))
	errc := make(chan error, 1)
	go func() { errc <- svc.ListenAndServe() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		svc.Shutdown(ctx)
		<-errc
	})
	// Wait for every target to actually be bound before returning.
	for _, tg := range cfg.Targets {
		waitBound(t, svc, tg.Name)
	}
	return svc
}

func waitBound(t *testing.T, svc *Service, target string) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if _, ok := svc.Addr(target); ok {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("target %s never bound", target)
}

// tcpEcho listens on a random port and echoes back everything it reads,
// unmodified, until the connection closes.
func tcpEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.Close() }()
		}
	}()
	return ln.Addr().String()
}

func udpEcho(t *testing.T) string {
	t.Helper()
	addr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, 65536)
		for {
			n, src, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			conn.WriteToUDP(buf[:n], src)
		}
	}()
	return conn.LocalAddr().String()
}

func TestTCPRelayForwardsAndCaptures(t *testing.T) {
	up := tcpEcho(t)
	sink := &fakeSink{}
	svc := startService(t, testConfig(Target{Name: "t1", Protocol: model.RelayTCP, Listen: "127.0.0.1:0", Upstream: up}), sink)
	addr, _ := svc.Addr("t1")

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "hello" {
		t.Fatalf("echo = %q", buf)
	}
	c.Close()

	// Give the session time to close and record.
	var sess *model.RelaySession
	for i := 0; i < 200; i++ {
		sess = sink.firstSession()
		if sess != nil && !sess.ClosedAt.IsZero() {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if sess == nil || sess.ClosedAt.IsZero() {
		t.Fatalf("session never closed: %+v", sess)
	}
	if sess.BytesUp != 5 || sess.BytesDown != 5 || sess.Protocol != model.RelayTCP {
		t.Fatalf("session = %+v", sess)
	}
	chunks := sink.chunksFor(sess.ID)
	if len(chunks) != 2 {
		t.Fatalf("expected 2 chunks (up+down), got %d: %+v", len(chunks), chunks)
	}
	var gotUp, gotDown bool
	for _, ch := range chunks {
		if ch.Direction == model.RelayUp && string(ch.Data) == "hello" {
			gotUp = true
		}
		if ch.Direction == model.RelayDown && string(ch.Data) == "hello" {
			gotDown = true
		}
	}
	if !gotUp || !gotDown {
		t.Fatalf("chunks = %+v", chunks)
	}
}

func TestTCPRelayDialFailureIsRecorded(t *testing.T) {
	sink := &fakeSink{}
	// Nothing listens here: dial must fail fast and be recorded, not crash.
	svc := startService(t, testConfig(Target{Name: "t1", Protocol: model.RelayTCP, Listen: "127.0.0.1:0", Upstream: "127.0.0.1:1"}), sink)
	addr, _ := svc.Addr("t1")

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()

	var sess *model.RelaySession
	for i := 0; i < 200; i++ {
		sess = sink.firstSession()
		if sess != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if sess == nil || sess.Error == "" {
		t.Fatalf("session = %+v", sess)
	}
}

func TestUDPRelayForwardsAndGroupsSessionByClientAddr(t *testing.T) {
	up := udpEcho(t)
	sink := &fakeSink{}
	svc := startService(t, testConfig(Target{Name: "t1", Protocol: model.RelayUDP, Listen: "127.0.0.1:0", Upstream: up}), sink)
	addr, _ := svc.Addr("t1")
	raddr, _ := net.ResolveUDPAddr("udp", addr)

	c, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for i := 0; i < 3; i++ {
		if _, err := c.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 4)
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.ReadFull(c, buf); err != nil {
			t.Fatal(err)
		}
		if string(buf) != "ping" {
			t.Fatalf("echo = %q", buf)
		}
	}

	// All 3 datagrams must share ONE session (grouped by client source addr).
	var n int
	for i := 0; i < 200; i++ {
		sink.mu.Lock()
		n = len(sink.sessions)
		sink.mu.Unlock()
		if n >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if n != 1 {
		t.Fatalf("expected exactly 1 UDP session, got %d", n)
	}
	sink.mu.Lock()
	sessID := sink.sessions[0].ID
	sink.mu.Unlock()
	for i := 0; i < 200; i++ {
		if len(sink.chunksFor(sessID)) >= 6 { // 3 up + 3 down
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := len(sink.chunksFor(sessID)); got != 6 {
		t.Fatalf("expected 6 chunks, got %d", got)
	}
}

func TestUDPIdleSessionIsEvicted(t *testing.T) {
	up := udpEcho(t)
	sink := &fakeSink{}
	cfg := testConfig(Target{Name: "t1", Protocol: model.RelayUDP, Listen: "127.0.0.1:0", Upstream: up})
	cfg.UDPIdleTimeout = 50 * time.Millisecond
	svc := startService(t, cfg, sink)
	addr, _ := svc.Addr("t1")
	raddr, _ := net.ResolveUDPAddr("udp", addr)

	c, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("x"))
	buf := make([]byte, 1)
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	io.ReadFull(c, buf)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		sink.mu.Lock()
		closed := len(sink.sessions) == 1 && !sink.sessions[0].ClosedAt.IsZero()
		sink.mu.Unlock()
		if closed {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("idle UDP session was never evicted/closed")
}

func TestCaptureCapStopsStoringButKeepsForwarding(t *testing.T) {
	up := tcpEcho(t)
	sink := &fakeSink{}
	cfg := testConfig(Target{Name: "t1", Protocol: model.RelayTCP, Listen: "127.0.0.1:0", Upstream: up})
	cfg.MaxCapture = 10 // tiny cap
	svc := startService(t, cfg, sink)
	addr, _ := svc.Addr("t1")

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	payload := []byte("this payload is much longer than the ten byte cap")
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("full payload must still be forwarded regardless of the cap, got %q", got)
	}
	c.Close()

	var sessID int64
	for i := 0; i < 200; i++ {
		sink.mu.Lock()
		if len(sink.sessions) > 0 {
			sessID = sink.sessions[0].ID
		}
		sink.mu.Unlock()
		if sessID != 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	var upChunks []*model.RelayChunk
	for i := 0; i < 200; i++ {
		upChunks = nil
		for _, ch := range sink.chunksFor(sessID) {
			if ch.Direction == model.RelayUp {
				upChunks = append(upChunks, ch)
			}
		}
		if len(upChunks) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(upChunks) != 1 {
		t.Fatalf("expected exactly one stored 'up' chunk (cap reached immediately after), got %d", len(upChunks))
	}
	ch := upChunks[0]
	if len(ch.Data) != 10 {
		t.Fatalf("stored data = %d bytes, want capped to 10", len(ch.Data))
	}
	if int(ch.DataSize) != len(payload) {
		t.Fatalf("DataSize = %d, want real size %d", ch.DataSize, len(payload))
	}
	if !ch.DataTruncated() {
		t.Fatal("chunk should report as truncated")
	}
	if ch.Note == "" {
		t.Fatal("expected a note explaining the cap")
	}
}

func TestConcurrentSessionsDoNotBlockEachOther(t *testing.T) {
	up := tcpEcho(t)
	sink := &fakeSink{}
	svc := startService(t, testConfig(Target{Name: "t1", Protocol: model.RelayTCP, Listen: "127.0.0.1:0", Upstream: up}), sink)
	addr, _ := svc.Addr("t1")

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := net.Dial("tcp", addr)
			if err != nil {
				t.Error(err)
				return
			}
			defer c.Close()
			c.Write([]byte("hi"))
			buf := make([]byte, 2)
			c.SetReadDeadline(time.Now().Add(3 * time.Second))
			if _, err := io.ReadFull(c, buf); err != nil {
				t.Error(err)
			}
		}()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent sessions did not all complete in time")
	}
}
