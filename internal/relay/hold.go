package relay

import (
	"context"
	"sort"
	"sync"
	"time"

	"proxyscope/internal/model"
)

// holdQueue is the relay's manual-intercept pause point: the byte-stream
// analog of intercept.Manager, deliberately copying its concurrency pattern
// (no worker goroutine; ownership of an item is decided by removing it from
// the map under the mutex; the owner sends once on a size-1 buffered
// channel so it never blocks) rather than reusing intercept.Manager itself.
// It cannot reuse Manager directly: Manager's exported API (HoldRequest/
// HoldResponse) is typed on model.Request/model.Response, which carry
// method/URL/headers/status that a raw byte chunk simply does not have.
// model.Verdict/Outcome/ErrPendingGone, which are already payload-agnostic,
// are reused as-is (see model/relay.go). See CLAUDE.md for the full
// rationale.
//
// Unlike Manager, settings are keyed per relay target (a target's "up"/
// "down" pause points are independent of every other target's), so one
// holdQueue instance serves every configured target rather than the whole
// app owning a single flat pair of toggles.
type holdQueue struct {
	timeout time.Duration // 0 = wait until resolved or the connection goes away

	mu       sync.Mutex
	settings map[string]model.RelaySettings // by target name
	nextID   int64
	items    map[int64]*heldChunk
}

type heldChunk struct {
	sum  model.RelayPendingSummary
	data *model.Chunk // snapshot as held, for the Equal comparison on resolve
	ch   chan model.RelayResolution
}

// newHoldQueue creates a holdQueue. Held chunks auto-forward unmodified
// after timeout (0 disables the timeout).
func newHoldQueue(timeout time.Duration) *holdQueue {
	return &holdQueue{timeout: timeout, settings: map[string]model.RelaySettings{}, items: map[int64]*heldChunk{}}
}

// Settings returns the current pause-point toggles for target.
func (q *holdQueue) Settings(target string) model.RelaySettings {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.settings[target]
}

// SetSettings changes target's toggles. Turning a direction off immediately
// releases everything held at it for that target, unmodified.
func (q *holdQueue) SetSettings(target string, s model.RelaySettings) {
	q.mu.Lock()
	old := q.settings[target]
	q.settings[target] = s
	var release []*heldChunk
	for id, it := range q.items {
		if it.sum.Target != target {
			continue
		}
		if (it.sum.Direction == model.RelayUp && old.Up && !s.Up) ||
			(it.sum.Direction == model.RelayDown && old.Down && !s.Down) {
			delete(q.items, id)
			release = append(release, it)
		}
	}
	q.mu.Unlock()
	for _, it := range release {
		it.ch <- model.RelayResolution{Note: "forwarded unmodified because relay intercept was turned off"}
	}
}

// Hold blocks until the chunk is resolved, times out, or ctx is done,
// applying the user's edits to data in place. It returns immediately,
// unmodified, if target/direction is not currently held.
//
// Unlike intercept.Manager (where ctx is each HTTP request's own context,
// cancelled the instant that specific client disconnects), the caller here
// passes the relay Service's shutdown context: raw TCP/UDP has no
// net/http-style machinery that hands a relay connection its own
// live-cancelled-on-disconnect context for free, and building one would
// need a dedicated watcher goroutine per held chunk. So a held relay chunk
// releases on user action, -intercept-timeout, or process shutdown, but
// not on the specific connection going away mid-hold (the timeout is what
// bounds that case). See CLAUDE.md for the full rationale.
func (q *holdQueue) Hold(ctx context.Context, target string, sessionID int64, dir model.RelayDirection, data *model.Chunk) model.Outcome {
	it := q.enqueue(target, sessionID, dir, data)
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

func (q *holdQueue) enqueue(target string, sessionID int64, dir model.RelayDirection, data *model.Chunk) *heldChunk {
	q.mu.Lock()
	defer q.mu.Unlock()
	s := q.settings[target]
	if (dir == model.RelayUp && !s.Up) || (dir == model.RelayDown && !s.Down) {
		return nil
	}
	q.nextID++
	it := &heldChunk{
		sum: model.RelayPendingSummary{
			ID: q.nextID, Target: target, SessionID: sessionID, Direction: dir, Size: len(data.Data), Created: time.Now(),
		},
		data: data.Clone(),
		ch:   make(chan model.RelayResolution, 1),
	}
	if q.timeout > 0 {
		exp := it.sum.Created.Add(q.timeout)
		it.sum.Expires = &exp
	}
	q.items[it.sum.ID] = it
	return it
}

// wait blocks until it is resolved, times out, or ctx is done.
func (q *holdQueue) wait(ctx context.Context, it *heldChunk) model.RelayResolution {
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
		// The service is shutting down (see Hold's doc comment): forward
		// unmodified rather than dropping, since the connection itself is
		// still very much alive and dropping would corrupt its byte stream
		// for no reason.
		if q.take(it) {
			return model.RelayResolution{Note: "forwarded unmodified because ProxyScope is shutting down"}
		}
	}
	return <-it.ch // Resolve/SetSettings/shutdown won the race and is sending
}

// take removes it from the queue, reporting whether the caller now owns it.
func (q *holdQueue) take(it *heldChunk) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.items[it.sum.ID] != it {
		return false
	}
	delete(q.items, it.sum.ID)
	return true
}

// Resolve completes a held item. It returns model.ErrPendingGone if the item
// was already resolved, timed out, or its connection went away.
func (q *holdQueue) Resolve(id int64, res model.RelayResolution) error {
	q.mu.Lock()
	it, ok := q.items[id]
	if ok {
		delete(q.items, id)
	}
	q.mu.Unlock()
	if !ok {
		return model.ErrPendingGone
	}
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
