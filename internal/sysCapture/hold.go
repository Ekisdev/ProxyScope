package sysCapture

import (
	"context"
	"sort"
	"sync"
	"time"

	"proxyscope/internal/model"
)

// holdQueue is sysCapture's manual-intercept pause point: the same
// concurrency pattern as relay.holdQueue (no worker goroutine; ownership of
// a held item decided by removing it from the map under the mutex; the
// owner sends once on a size-1 buffered channel so it never blocks), kept
// as its own small implementation rather than importing internal/relay --
// leaf packages depend at most on model (see CLAUDE.md), and sysCapture is
// a leaf exactly like relay is. It reuses model.RelaySettings/
// RelayPendingSummary/RelayPending/RelayResolution/Chunk as-is: a captured
// packet's payload is held/edited exactly like a relay chunk (see
// packet.go for the one real difference -- the TCP same-length constraint,
// enforced in Resolve below, not in this file).
//
// Unlike relay.holdQueue (settings keyed per target, since each -relay
// target's toggles are independent), there is exactly one configured
// filter in this phase, so settings are a single flat model.RelaySettings,
// matching intercept.Manager's flat pair more closely than relay's map.
type holdQueue struct {
	timeout time.Duration // 0 = wait until resolved or shutdown

	mu       sync.Mutex
	settings model.RelaySettings
	nextID   int64
	items    map[int64]*heldPacket
}

type heldPacket struct {
	sum      model.RelayPendingSummary
	data     *model.Chunk // snapshot as held, for the Equal comparison on resolve
	protocol model.RelayProtocol
	ch       chan model.RelayResolution
}

func newHoldQueue(timeout time.Duration) *holdQueue {
	return &holdQueue{timeout: timeout, items: map[int64]*heldPacket{}}
}

// Settings returns the current pause-point toggles.
func (q *holdQueue) Settings() model.RelaySettings {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.settings
}

// SetSettings changes the toggles. Turning a direction off immediately
// releases everything currently held at it, unmodified.
func (q *holdQueue) SetSettings(s model.RelaySettings) {
	q.mu.Lock()
	old := q.settings
	q.settings = s
	var release []*heldPacket
	for id, it := range q.items {
		if (it.sum.Direction == model.RelayUp && old.Up && !s.Up) ||
			(it.sum.Direction == model.RelayDown && old.Down && !s.Down) {
			delete(q.items, id)
			release = append(release, it)
		}
	}
	q.mu.Unlock()
	for _, it := range release {
		it.ch <- model.RelayResolution{Note: "forwarded unmodified because system-capture intercept was turned off"}
	}
}

// Hold blocks until the packet's payload is resolved, times out, or ctx is
// done, applying the user's edits to data in place. It returns immediately,
// unmodified, if direction is not currently held.
//
// Holding one packet pauses every other packet on this filter until it is
// resolved: there is exactly one WinDivert handle and one receive loop for
// the whole capture (see capture_windows.go), so unlike per-connection TCP
// relay holds, this mirrors relay's UDP holds, which share one reader per
// target for the same reason. -intercept-timeout is the backstop; keep the
// intercept toggles off unless actively editing (see README).
func (q *holdQueue) Hold(ctx context.Context, sessionID int64, dir model.RelayDirection, protocol model.RelayProtocol, filter string, data *model.Chunk) model.Outcome {
	it := q.enqueue(sessionID, dir, protocol, filter, data)
	if it == nil {
		return model.Outcome{}
	}
	res := q.wait(ctx, it)
	out := model.Outcome{Note: res.Note}
	if res.Drop {
		out.Verdict = model.VerdictDrop
		return out
	}
	if res.Chunk != nil && !res.Chunk.Equal(it.data) {
		*data = *res.Chunk.Clone()
		out.Edited = true
	}
	return out
}

func (q *holdQueue) enqueue(sessionID int64, dir model.RelayDirection, protocol model.RelayProtocol, filter string, data *model.Chunk) *heldPacket {
	q.mu.Lock()
	defer q.mu.Unlock()
	s := q.settings
	if (dir == model.RelayUp && !s.Up) || (dir == model.RelayDown && !s.Down) {
		return nil
	}
	q.nextID++
	it := &heldPacket{
		sum: model.RelayPendingSummary{
			ID: q.nextID, Target: filter, SessionID: sessionID, Direction: dir, Size: len(data.Data), Created: time.Now(),
		},
		data:     data.Clone(),
		protocol: protocol,
		ch:       make(chan model.RelayResolution, 1),
	}
	if q.timeout > 0 {
		exp := it.sum.Created.Add(q.timeout)
		it.sum.Expires = &exp
	}
	q.items[it.sum.ID] = it
	return it
}

func (q *holdQueue) wait(ctx context.Context, it *heldPacket) model.RelayResolution {
	var expired <-chan time.Time
	if q.timeout > 0 {
		t := time.NewTimer(q.timeout)
		defer t.Stop()
		expired = t.C
	}
	select {
	case res := <-it.ch:
		return res
	case <-expired:
		if q.take(it) {
			return model.RelayResolution{Note: "auto-forwarded unmodified after " + q.timeout.String() + " (intercept timeout)"}
		}
	case <-ctx.Done():
		// Shutdown only (see Hold's doc comment): forward unmodified, not
		// drop -- a captured connection is still alive on the wire and
		// dropping one packet mid-hold would corrupt its stream for no
		// reason, exactly like relay.holdQueue's shutdown release.
		if q.take(it) {
			return model.RelayResolution{Note: "forwarded unmodified because ProxyScope is shutting down"}
		}
	}
	return <-it.ch // Resolve/SetSettings/shutdown won the race and is sending
}

func (q *holdQueue) take(it *heldPacket) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.items[it.sum.ID] != it {
		return false
	}
	delete(q.items, it.sum.ID)
	return true
}

// Resolve completes a held item. It returns model.ErrPendingGone if the item
// was already resolved, timed out, or released, and ErrTCPPayloadLengthMismatch
// (leaving the item still held) if a TCP edit changed the payload length.
func (q *holdQueue) Resolve(id int64, res model.RelayResolution) error {
	q.mu.Lock()
	it, ok := q.items[id]
	if !ok {
		q.mu.Unlock()
		return model.ErrPendingGone
	}
	if it.protocol == model.RelayTCP && res.Chunk != nil && len(res.Chunk.Data) != len(it.data.Data) {
		q.mu.Unlock()
		return ErrTCPPayloadLengthMismatch
	}
	delete(q.items, id)
	q.mu.Unlock()
	it.ch <- res
	return nil
}

// List returns the held items, oldest first.
func (q *holdQueue) List() []model.RelayPendingSummary {
	q.mu.Lock()
	out := make([]model.RelayPendingSummary, 0, len(q.items))
	for _, it := range q.items {
		out = append(out, it.sum)
	}
	q.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Get returns a copy of a held item, or model.ErrPendingGone.
func (q *holdQueue) Get(id int64) (*model.RelayPending, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	it, ok := q.items[id]
	if !ok {
		return nil, model.ErrPendingGone
	}
	return &model.RelayPending{RelayPendingSummary: it.sum, Chunk: it.data.Clone()}, nil
}
