package sysCapture

import (
	"context"
	"strconv"
	"sync"
	"testing"
	"time"

	"proxyscope/internal/model"
)

func waitPending(t *testing.T, q *holdQueue, n int) []model.RelayPendingSummary {
	t.Helper()
	for i := 0; i < 200; i++ {
		if l := q.List(); len(l) == n {
			return l
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("expected %d pending items, have %d", n, len(q.List()))
	return nil
}

func TestHoldOffByDefaultPassesThrough(t *testing.T) {
	q := newHoldQueue(time.Second)
	data := &model.Chunk{Data: []byte("hi")}
	out := q.Hold(context.Background(), 1, model.RelayUp, model.RelayTCP, "filter", data)
	if out.Verdict != model.VerdictForward || out.Edited {
		t.Fatalf("outcome = %+v", out)
	}
	if len(q.List()) != 0 {
		t.Fatal("nothing should be queued while off")
	}
}

func TestHoldEditAndForward(t *testing.T) {
	q := newHoldQueue(5 * time.Second)
	q.SetSettings(model.RelaySettings{Up: true})
	data := &model.Chunk{Data: []byte("orig")}
	done := make(chan model.Outcome)
	go func() { done <- q.Hold(context.Background(), 42, model.RelayUp, model.RelayUDP, "f", data) }()

	l := waitPending(t, q, 1)
	if l[0].Target != "f" || l[0].SessionID != 42 || l[0].Direction != model.RelayUp || l[0].Size != 4 {
		t.Fatalf("summary = %+v", l[0])
	}
	p, err := q.Get(l[0].ID)
	if err != nil || string(p.Chunk.Data) != "orig" {
		t.Fatalf("get = %+v %v", p, err)
	}
	// UDP: a length-changing edit is allowed (no TCP sequence numbers to desync).
	edited := &model.Chunk{Data: []byte("edited!!")}
	if err := q.Resolve(l[0].ID, model.RelayResolution{Chunk: edited}); err != nil {
		t.Fatal(err)
	}
	out := <-done
	if !out.Edited || string(data.Data) != "edited!!" {
		t.Fatalf("edit not applied: %+v %+v", out, data)
	}
	if err := q.Resolve(l[0].ID, model.RelayResolution{}); err != model.ErrPendingGone {
		t.Fatalf("second resolve = %v, want ErrPendingGone", err)
	}
}

// TestHoldTCPLengthMismatchRejected is the dedicated test for the
// explicitly required rejection path: a TCP edit that changes the
// payload's length must fail with a specific, named error (never a
// generic validation error, and never silently applied), and the item
// must remain held so the user can retry with a same-length edit.
func TestHoldTCPLengthMismatchRejected(t *testing.T) {
	q := newHoldQueue(5 * time.Second)
	q.SetSettings(model.RelaySettings{Up: true})
	data := &model.Chunk{Data: []byte("orig")} // 4 bytes
	done := make(chan model.Outcome)
	go func() { done <- q.Hold(context.Background(), 1, model.RelayUp, model.RelayTCP, "f", data) }()
	l := waitPending(t, q, 1)

	// Shorter: rejected.
	if err := q.Resolve(l[0].ID, model.RelayResolution{Chunk: &model.Chunk{Data: []byte("abc")}}); err != ErrTCPPayloadLengthMismatch {
		t.Fatalf("err = %v, want ErrTCPPayloadLengthMismatch", err)
	}
	// Longer: also rejected.
	if err := q.Resolve(l[0].ID, model.RelayResolution{Chunk: &model.Chunk{Data: []byte("abcdefgh")}}); err != ErrTCPPayloadLengthMismatch {
		t.Fatalf("err = %v, want ErrTCPPayloadLengthMismatch", err)
	}
	// Still held after both rejections.
	if l := q.List(); len(l) != 1 {
		t.Fatalf("item should still be held after a rejected edit, got %+v", l)
	}
	// A same-length edit succeeds.
	if err := q.Resolve(l[0].ID, model.RelayResolution{Chunk: &model.Chunk{Data: []byte("NEWD")}}); err != nil {
		t.Fatalf("same-length edit should succeed: %v", err)
	}
	out := <-done
	if !out.Edited || string(data.Data) != "NEWD" {
		t.Fatalf("same-length edit not applied: %+v %+v", out, data)
	}
}

func TestHoldTCPDropIgnoresLengthConstraint(t *testing.T) {
	q := newHoldQueue(5 * time.Second)
	q.SetSettings(model.RelaySettings{Up: true})
	done := make(chan model.Outcome)
	go func() {
		done <- q.Hold(context.Background(), 1, model.RelayUp, model.RelayTCP, "f", &model.Chunk{Data: []byte("orig")})
	}()
	l := waitPending(t, q, 1)
	// Drop carries no replacement Chunk, so the length check (which only
	// fires when res.Chunk != nil) must not block it.
	if err := q.Resolve(l[0].ID, model.RelayResolution{Drop: true}); err != nil {
		t.Fatal(err)
	}
	if out := <-done; out.Verdict != model.VerdictDrop {
		t.Fatalf("outcome = %+v", out)
	}
}

func TestHoldUnchangedIsNotReportedAsEdited(t *testing.T) {
	q := newHoldQueue(5 * time.Second)
	q.SetSettings(model.RelaySettings{Down: true})
	done := make(chan model.Outcome)
	go func() {
		done <- q.Hold(context.Background(), 1, model.RelayDown, model.RelayTCP, "f", &model.Chunk{Data: []byte("x")})
	}()
	l := waitPending(t, q, 1)
	p, _ := q.Get(l[0].ID)
	q.Resolve(l[0].ID, model.RelayResolution{Chunk: p.Chunk})
	if out := <-done; out.Edited {
		t.Fatal("identical chunk must not count as edited")
	}
}

func TestHoldDrop(t *testing.T) {
	q := newHoldQueue(5 * time.Second)
	q.SetSettings(model.RelaySettings{Up: true})
	done := make(chan model.Outcome)
	go func() {
		done <- q.Hold(context.Background(), 1, model.RelayUp, model.RelayUDP, "f", &model.Chunk{Data: []byte("x")})
	}()
	l := waitPending(t, q, 1)
	q.Resolve(l[0].ID, model.RelayResolution{Drop: true})
	if out := <-done; out.Verdict != model.VerdictDrop {
		t.Fatalf("outcome = %+v", out)
	}
}

func TestHoldOnlyAppliesToItsOwnDirection(t *testing.T) {
	q := newHoldQueue(5 * time.Second)
	q.SetSettings(model.RelaySettings{Up: true}) // up only
	if out := q.Hold(context.Background(), 1, model.RelayDown, model.RelayUDP, "f", &model.Chunk{Data: []byte("x")}); out.Verdict != model.VerdictForward {
		t.Fatalf("down should not be held: %+v", out)
	}
	if len(q.List()) != 0 {
		t.Fatal("nothing should have been queued")
	}
}

func TestHoldManyResolveIndependently(t *testing.T) {
	q := newHoldQueue(10 * time.Second)
	q.SetSettings(model.RelaySettings{Up: true})
	const n = 25
	var wg sync.WaitGroup
	verdicts := make([]model.Verdict, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			verdicts[i] = q.Hold(context.Background(), int64(i), model.RelayUp, model.RelayUDP, "f", &model.Chunk{Data: []byte(strconv.Itoa(i))}).Verdict
		}(i)
	}
	l := waitPending(t, q, n)
	for i := len(l) - 1; i >= 0; i-- {
		drop := l[i].SessionID%2 == 0
		if err := q.Resolve(l[i].ID, model.RelayResolution{Drop: drop}); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
	for i, v := range verdicts {
		want := model.VerdictForward
		if i%2 == 0 {
			want = model.VerdictDrop
		}
		if v != want {
			t.Fatalf("item %d: verdict %v, want %v", i, v, want)
		}
	}
	if len(q.List()) != 0 {
		t.Fatal("queue should be empty")
	}
}

func TestHoldTimeoutAutoForwards(t *testing.T) {
	q := newHoldQueue(50 * time.Millisecond)
	q.SetSettings(model.RelaySettings{Up: true})
	done := make(chan model.Outcome)
	go func() {
		done <- q.Hold(context.Background(), 1, model.RelayUp, model.RelayUDP, "f", &model.Chunk{Data: []byte("x")})
	}()
	waitPending(t, q, 1)
	select {
	case out := <-done:
		if out.Edited || out.Verdict != model.VerdictForward || out.Note == "" {
			t.Fatalf("outcome = %+v", out)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout did not release the held chunk")
	}
}

func TestHoldShutdownContextReleasesUnmodified(t *testing.T) {
	q := newHoldQueue(10 * time.Second)
	q.SetSettings(model.RelaySettings{Up: true})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan model.Outcome)
	go func() { done <- q.Hold(ctx, 1, model.RelayUp, model.RelayUDP, "f", &model.Chunk{Data: []byte("x")}) }()
	waitPending(t, q, 1)
	cancel()
	select {
	case out := <-done:
		if out.Verdict != model.VerdictForward || out.Edited {
			t.Fatalf("shutdown must forward unmodified, got %+v", out)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancelled context did not release the held chunk")
	}
}

func TestHoldTurningOffReleasesHeldItems(t *testing.T) {
	q := newHoldQueue(10 * time.Second)
	q.SetSettings(model.RelaySettings{Up: true, Down: true})
	upDone := make(chan model.Outcome, 1)
	downDone := make(chan model.Outcome, 1)
	go func() {
		upDone <- q.Hold(context.Background(), 1, model.RelayUp, model.RelayUDP, "f", &model.Chunk{Data: []byte("u")})
	}()
	go func() {
		downDone <- q.Hold(context.Background(), 1, model.RelayDown, model.RelayUDP, "f", &model.Chunk{Data: []byte("d")})
	}()
	waitPending(t, q, 2)

	q.SetSettings(model.RelaySettings{Up: false, Down: true}) // release only "up"
	select {
	case out := <-upDone:
		if out.Verdict != model.VerdictForward {
			t.Fatalf("up outcome = %+v", out)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("turning off 'up' did not release it")
	}
	if l := q.List(); len(l) != 1 || l[0].Direction != model.RelayDown {
		t.Fatalf("expected only the 'down' item still held, got %+v", l)
	}
	q.Resolve(q.List()[0].ID, model.RelayResolution{})
	<-downDone
}
