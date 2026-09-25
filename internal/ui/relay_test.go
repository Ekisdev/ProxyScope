package ui

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"proxyscope/internal/model"
	"proxyscope/internal/relay"
	"proxyscope/internal/store"
)

// tcpEcho listens on a random port and echoes back everything it reads.
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

// newRelayAPI starts a real relay.Service (with a real store, so the UI's
// read side has real data to serve) targeting a TCP echo upstream, and
// returns the UI handler along with enough to drive a client connection
// through it.
func newRelayAPI(t *testing.T) (h http.Handler, addr string, st *store.Store) {
	t.Helper()
	up := tcpEcho(t)
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	svc := relay.New(relay.Config{
		Targets:          []relay.Target{{Name: "t1", Protocol: model.RelayTCP, Listen: "127.0.0.1:0", Upstream: up}},
		DialTimeout:      2 * time.Second,
		MaxCapture:       1 << 20,
		UDPIdleTimeout:   time.Minute,
		InterceptTimeout: 10 * time.Second,
	}, st, slog.New(slog.DiscardHandler))
	errc := make(chan error, 1)
	go func() { errc <- svc.ListenAndServe() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		svc.Shutdown(ctx)
		<-errc
	})
	for i := 0; i < 200; i++ {
		if a, ok := svc.Addr("t1"); ok {
			addr = a
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if addr == "" {
		t.Fatal("relay target never bound")
	}

	s := New("127.0.0.1:0", Deps{Store: st, Relay: svc}, slog.New(slog.DiscardHandler))
	return s.server.Handler, addr, st
}

func TestRelayStateShowsTargetAndDefaultSettings(t *testing.T) {
	h, _, _ := newRelayAPI(t)
	var st relayState
	json.Unmarshal(call(h, "GET", "/api/relay", "").Body.Bytes(), &st)
	if len(st.Targets) != 1 || st.Targets[0].Name != "t1" || st.Targets[0].Protocol != model.RelayTCP {
		t.Fatalf("state = %+v", st)
	}
	if st.Targets[0].Settings.Up || st.Targets[0].Settings.Down {
		t.Fatalf("intercept must default to off: %+v", st.Targets[0].Settings)
	}
	if st.TimeoutSeconds != 10 {
		t.Fatalf("timeout = %v", st.TimeoutSeconds)
	}
}

func TestRelayInterceptEditForwardAndSessionHistory(t *testing.T) {
	h, addr, _ := newRelayAPI(t)

	// Enable "up" intercept via the UI endpoint.
	w := call(h, "PUT", "/api/relay/targets/t1/settings", `{"up":true}`)
	if w.Code != 200 {
		t.Fatalf("settings = %d %s", w.Code, w.Body)
	}

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	writeErr := make(chan error, 1)
	go func() { _, err := conn.Write([]byte("orig")); writeErr <- err }()

	// Find the held chunk via the pending list.
	var pendingID int64
	for i := 0; i < 200; i++ {
		var st relayState
		json.Unmarshal(call(h, "GET", "/api/relay", "").Body.Bytes(), &st)
		if len(st.Pending) == 1 {
			pendingID = st.Pending[0].ID
			if st.Pending[0].Direction != model.RelayUp || st.Pending[0].Target != "t1" {
				t.Fatalf("pending summary = %+v", st.Pending[0])
			}
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if pendingID == 0 {
		t.Fatal("chunk was never held")
	}

	var pv relayPendingView
	json.Unmarshal(call(h, "GET", "/api/relay/pending/"+itoa(pendingID), "").Body.Bytes(), &pv)
	if pv.Hex != hex.EncodeToString([]byte("orig")) {
		t.Fatalf("pending hex = %q", pv.Hex)
	}

	// Forward edited: "orig" -> "edited!!" (as hex, with some whitespace to
	// prove parseHexEdit tolerates a pasted-in dump).
	editedHex := hex.EncodeToString([]byte("edited!!"))
	spaced := editedHex[:2] + " " + editedHex[2:]
	w = call(h, "POST", "/api/relay/pending/"+itoa(pendingID)+"/forward", `{"hex":"`+spaced+`"}`)
	if w.Code != 204 {
		t.Fatalf("forward = %d %s", w.Code, w.Body)
	}
	if err := <-writeErr; err != nil {
		t.Fatal(err)
	}

	got := make([]byte, 8)
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "edited!!" {
		t.Fatalf("echo = %q, want the edited bytes", got)
	}
	conn.Close()

	// Second resolve of the same id must now be gone.
	if w := call(h, "POST", "/api/relay/pending/"+itoa(pendingID)+"/forward", ""); w.Code != 409 {
		t.Fatalf("second resolve = %d, want 409", w.Code)
	}

	// The session shows up in history with the edited chunk recorded.
	var sessionID int64
	for i := 0; i < 200; i++ {
		var sessions []model.RelaySessionSummary
		json.Unmarshal(call(h, "GET", "/api/relay/sessions?target=t1", "").Body.Bytes(), &sessions)
		if len(sessions) == 1 && sessions[0].ClosedAt != nil {
			sessionID = sessions[0].ID
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if sessionID == 0 {
		t.Fatal("session never closed/recorded")
	}

	var detail relaySessionDetailView
	json.Unmarshal(call(h, "GET", "/api/relay/sessions/"+itoa(sessionID), "").Body.Bytes(), &detail)
	if detail.Target != "t1" || len(detail.Chunks) != 2 {
		t.Fatalf("detail = %+v", detail)
	}
	up := detail.Chunks[0]
	if up.Direction != "up" || !up.Edited || !strings.Contains(up.Hex, "65 64 69 74 65 64 21 21") { // "edited!!"
		t.Fatalf("up chunk = %+v", up)
	}
	down := detail.Chunks[1]
	if down.Direction != "down" || down.Edited {
		t.Fatalf("down chunk = %+v", down)
	}
}

func TestRelayDrop(t *testing.T) {
	h, addr, _ := newRelayAPI(t)
	call(h, "PUT", "/api/relay/targets/t1/settings", `{"up":true}`)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	go conn.Write([]byte("dropme"))

	var pendingID int64
	for i := 0; i < 200; i++ {
		var st relayState
		json.Unmarshal(call(h, "GET", "/api/relay", "").Body.Bytes(), &st)
		if len(st.Pending) == 1 {
			pendingID = st.Pending[0].ID
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if pendingID == 0 {
		t.Fatal("chunk was never held")
	}
	if w := call(h, "POST", "/api/relay/pending/"+itoa(pendingID)+"/drop", ""); w.Code != 204 {
		t.Fatalf("drop = %d %s", w.Code, w.Body)
	}
	// Nothing should ever arrive at the echo server / come back.
	conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("dropped chunk must not be forwarded")
	}
}
