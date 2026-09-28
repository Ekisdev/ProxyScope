package sysCapture

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"proxyscope/internal/model"
)

// fakeSink is an in-memory sysCapture.Sink for tests, mirroring the pattern
// internal/relay's test suite uses for its own fake sink.
type fakeSink struct {
	mu       sync.Mutex
	nextID   int64
	sessions map[int64]*model.RelaySession
	chunks   []model.RelayChunk
}

func newFakeSink() *fakeSink { return &fakeSink{sessions: map[int64]*model.RelaySession{}} }

func (f *fakeSink) OpenSession(_ context.Context, s *model.RelaySession) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextID++
	s.ID = f.nextID
	cp := *s
	f.sessions[s.ID] = &cp
	return nil
}

func (f *fakeSink) CloseSession(_ context.Context, id int64, closedAt time.Time, bytesUp, bytesDown int64, errStr string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	sess := f.sessions[id]
	sess.ClosedAt = closedAt
	sess.BytesUp, sess.BytesDown, sess.Error = bytesUp, bytesDown, errStr
	return nil
}

func (f *fakeSink) SaveChunk(_ context.Context, c *model.RelayChunk) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.chunks = append(f.chunks, *c)
	return nil
}

func (f *fakeSink) session(id int64) *model.RelaySession {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := *f.sessions[id]
	return &cp
}

func (f *fakeSink) chunksFor(sessionID int64) []model.RelayChunk {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []model.RelayChunk
	for _, c := range f.chunks {
		if c.SessionID == sessionID {
			out = append(out, c)
		}
	}
	return out
}

func testService(t *testing.T, cfg Config, sink Sink) *Service {
	t.Helper()
	if cfg.MaxCapture == 0 {
		cfg.MaxCapture = 1 << 20
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = time.Minute
	}
	if cfg.Filter == "" {
		cfg.Filter = "tcp.DstPort == 9100"
	}
	return New(cfg, sink, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestProcessPacketUnparseablePassesThroughUncaptured(t *testing.T) {
	sink := newFakeSink()
	s := testService(t, Config{}, sink)
	pkt := []byte{0xFF, 0xFF, 0xFF} // not a valid IP packet at all
	out, drop := s.processPacket(pkt, true)
	if drop || string(out) != string(pkt) {
		t.Fatalf("out=%v drop=%v, want unmodified passthrough", out, drop)
	}
	sink.mu.Lock()
	n := len(sink.sessions)
	sink.mu.Unlock()
	if n != 0 {
		t.Fatal("an unparseable packet must not open a session")
	}
}

func TestProcessPacketOpensOneSessionForBothDirections(t *testing.T) {
	sink := newFakeSink()
	s := testService(t, Config{}, sink)

	out1 := buildIPv4TCP(t, "10.0.0.5", "1.2.3.4", 4444, 9100, tcpFlagSYN, []byte("req"))
	pkt, drop := s.processPacket(out1, true)
	if drop || string(pkt) != string(out1) {
		t.Fatalf("outbound: pkt=%v drop=%v", pkt, drop)
	}

	in1 := buildIPv4TCP(t, "1.2.3.4", "10.0.0.5", 9100, 4444, 0, []byte("resp"))
	pkt2, drop2 := s.processPacket(in1, false)
	if drop2 || string(pkt2) != string(in1) {
		t.Fatalf("inbound: pkt=%v drop=%v", pkt2, drop2)
	}

	sink.mu.Lock()
	n := len(sink.sessions)
	sink.mu.Unlock()
	if n != 1 {
		t.Fatalf("both directions of one flow must share one session, got %d sessions", n)
	}

	var sess *model.RelaySession
	for _, v := range sink.sessions {
		sess = v
	}
	if sess.Source != model.RelaySourceSysCapture {
		t.Fatalf("Source = %q, want %q", sess.Source, model.RelaySourceSysCapture)
	}
	if sess.ClientAddr != "10.0.0.5:4444" || sess.UpstreamAddr != "1.2.3.4:9100" {
		t.Fatalf("addrs = %s -> %s, want local=10.0.0.5:4444 upstream=1.2.3.4:9100", sess.ClientAddr, sess.UpstreamAddr)
	}
	if sess.Target != s.cfg.Filter {
		t.Fatalf("Target = %q, want the filter %q", sess.Target, s.cfg.Filter)
	}

	chunks := sink.chunksFor(sess.ID)
	if len(chunks) != 2 || chunks[0].Direction != model.RelayUp || chunks[1].Direction != model.RelayDown {
		t.Fatalf("chunks = %+v", chunks)
	}
	if string(chunks[0].Data) != "req" || string(chunks[1].Data) != "resp" {
		t.Fatalf("chunk payloads = %q, %q", chunks[0].Data, chunks[1].Data)
	}
}

func TestProcessPacketDifferentFlowsGetDifferentSessions(t *testing.T) {
	sink := newFakeSink()
	s := testService(t, Config{}, sink)
	a := buildIPv4UDP(t, "10.0.0.5", "1.2.3.4", 1111, 53, []byte("a"))
	b := buildIPv4UDP(t, "10.0.0.5", "1.2.3.4", 2222, 53, []byte("b")) // different local port
	s.processPacket(a, true)
	s.processPacket(b, true)
	sink.mu.Lock()
	n := len(sink.sessions)
	sink.mu.Unlock()
	if n != 2 {
		t.Fatalf("expected 2 distinct sessions, got %d", n)
	}
}

func TestProcessPacketDropNeverReinjected(t *testing.T) {
	sink := newFakeSink()
	s := testService(t, Config{}, sink)
	s.hold.SetSettings(model.RelaySettings{Up: true})

	pkt := buildIPv4TCP(t, "10.0.0.5", "1.2.3.4", 1, 9100, 0, []byte("secret"))
	done := make(chan struct{})
	var out []byte
	var drop bool
	go func() { out, drop = s.processPacket(pkt, true); close(done) }()

	l := waitPending(t, s.hold, 1)
	if err := s.hold.Resolve(l[0].ID, model.RelayResolution{Drop: true}); err != nil {
		t.Fatal(err)
	}
	<-done
	if !drop || out != nil {
		t.Fatalf("out=%v drop=%v, want drop with nil bytes", out, drop)
	}
}

func TestProcessPacketEditAppliesToReinjectedPacket(t *testing.T) {
	sink := newFakeSink()
	s := testService(t, Config{}, sink)
	s.hold.SetSettings(model.RelaySettings{Up: true})

	pkt := buildIPv4TCP(t, "10.0.0.5", "1.2.3.4", 1, 9100, 0, []byte("hello"))
	done := make(chan []byte)
	go func() { out, _ := s.processPacket(pkt, true); done <- out }()

	l := waitPending(t, s.hold, 1)
	if err := s.hold.Resolve(l[0].ID, model.RelayResolution{Chunk: &model.Chunk{Data: []byte("HELLO")}}); err != nil {
		t.Fatal(err)
	}
	out := <-done
	p, err := parsePacket(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(p.payload(out)) != "HELLO" {
		t.Fatalf("payload = %q, want HELLO", p.payload(out))
	}
}

func TestProcessPacketCaptureCapStopsStoringButKeepsForwarding(t *testing.T) {
	sink := newFakeSink()
	s := testService(t, Config{MaxCapture: 5}, sink)

	first := buildIPv4UDP(t, "10.0.0.5", "1.2.3.4", 1, 2, []byte("12345")) // exactly the cap
	second := buildIPv4UDP(t, "10.0.0.5", "1.2.3.4", 1, 2, []byte("more data"))

	out1, drop1 := s.processPacket(first, true)
	if drop1 || string(out1) != string(first) {
		t.Fatalf("first packet must still be forwarded in full: out=%v drop=%v", out1, drop1)
	}
	out2, drop2 := s.processPacket(second, true)
	if drop2 || string(out2) != string(second) {
		t.Fatalf("second packet must still be forwarded in full despite the cap: out=%v drop=%v", out2, drop2)
	}

	sink.mu.Lock()
	var sessID int64
	for id := range sink.sessions {
		sessID = id
	}
	sink.mu.Unlock()
	// The first packet lands exactly at the cap (5 of 5 bytes fit) and is
	// stored whole; the second is where the cap is actually exceeded, so it
	// gets one final zero-byte row explaining why, and nothing stored after
	// that -- exactly relay.Service.storeChunk's algorithm (see session.go).
	chunks := sink.chunksFor(sessID)
	if len(chunks) != 2 {
		t.Fatalf("expected two stored chunk rows (at-cap, then the capped marker), got %d: %+v", len(chunks), chunks)
	}
	if chunks[0].DataSize != 5 || len(chunks[0].Data) != 5 || chunks[0].Note != "" {
		t.Fatalf("first (at-cap) chunk should be stored whole with no note: %+v", chunks[0])
	}
	if chunks[1].DataSize != 9 || len(chunks[1].Data) != 0 || chunks[1].Note == "" {
		t.Fatalf("second chunk should record the real size, store nothing, and explain why: %+v", chunks[1])
	}
}

func TestServiceShutdownClosesOpenSessionsAndReleasesHolds(t *testing.T) {
	sink := newFakeSink()
	s := testService(t, Config{}, sink)
	s.hold.SetSettings(model.RelaySettings{Up: true})

	pkt := buildIPv4TCP(t, "10.0.0.5", "1.2.3.4", 1, 9100, 0, []byte("x"))
	done := make(chan struct{})
	go func() { s.processPacket(pkt, true); close(done) }()
	waitPending(t, s.hold, 1)

	if err := s.shutdownCommon(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown did not release the held packet")
	}

	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.sessions) != 1 {
		t.Fatalf("expected one session, got %d", len(sink.sessions))
	}
	for _, sess := range sink.sessions {
		if sess.ClosedAt.IsZero() {
			t.Fatal("shutdown must close every still-open session")
		}
	}
}
