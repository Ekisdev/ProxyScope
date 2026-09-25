// Package intercept implements the live intercept queue: requests and
// responses can be held before they continue, inspected and edited from the
// UI, then forwarded or dropped.
//
// Concurrency model: there is no worker goroutine. The proxy's own per-request
// goroutine calls HoldRequest/HoldResponse and blocks in a select until the
// user resolves the item, the auto-forward timeout fires, or the client goes
// away. A held message therefore blocks only its own request; everything else
// keeps flowing. Each item owns a buffered channel of size 1, and ownership of
// an item is decided under the manager's mutex (whoever removes it from the
// map owns it), so an item is resolved exactly once.
package intercept

import (
	"context"
	"sort"
	"sync"
	"time"

	"proxyscope/internal/model"
)

type item struct {
	sum  model.PendingSummary
	req  *model.Request  // snapshot; for response items the originating request
	resp *model.Response // snapshot; response items only
	ch   chan model.Resolution
}

// Manager is the intercept queue. It is safe for concurrent use. The zero
// settings (both pause points off) let everything through untouched.
type Manager struct {
	timeout time.Duration // 0 = wait until resolved or the client disconnects

	mu       sync.Mutex
	settings model.InterceptSettings
	nextID   int64
	items    map[int64]*item
}

// New creates a Manager. Held items auto-forward unmodified after timeout
// (0 disables the timeout).
func New(timeout time.Duration) *Manager {
	return &Manager{timeout: timeout, items: map[int64]*item{}}
}

// Timeout returns the auto-forward timeout (0 = none).
func (m *Manager) Timeout() time.Duration { return m.timeout }

// Settings returns the current pause-point toggles.
func (m *Manager) Settings() model.InterceptSettings {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.settings
}

// RequestEnabled reports whether requests are currently being held.
func (m *Manager) RequestEnabled() bool { return m.Settings().Request }

// ResponseEnabled reports whether responses are currently being held.
func (m *Manager) ResponseEnabled() bool { return m.Settings().Response }

// SetSettings changes the toggles. Turning a pause point off immediately
// releases everything held at it, unmodified, so nothing is left hanging.
func (m *Manager) SetSettings(s model.InterceptSettings) {
	m.mu.Lock()
	old := m.settings
	m.settings = s
	var release []*item
	for id, it := range m.items {
		if (it.sum.Kind == model.PendingRequest && old.Request && !s.Request) ||
			(it.sum.Kind == model.PendingResponse && old.Response && !s.Response) {
			delete(m.items, id)
			release = append(release, it)
		}
	}
	m.mu.Unlock()
	for _, it := range release {
		it.ch <- model.Resolution{Note: "forwarded unmodified because intercept was turned off"}
	}
}

// HoldRequest blocks until the request is resolved, then applies the user's
// edits to req in place. It returns immediately if request intercept is off.
func (m *Manager) HoldRequest(ctx context.Context, req *model.Request) model.Outcome {
	it := m.enqueue(model.PendingRequest, req, nil)
	if it == nil {
		return model.Outcome{}
	}
	res := m.wait(ctx, it)
	out := model.Outcome{Note: res.Note}
	if res.Drop {
		out.Verdict = model.VerdictDrop
		return out
	}
	if res.Request != nil && !res.Request.Equal(it.req) {
		*req = *res.Request.Clone()
		out.Edited = true
	}
	return out
}

// HoldResponse blocks until the response is resolved, then applies the user's
// edits to resp in place. req is the request that produced it (context only).
// It returns immediately if response intercept is off.
func (m *Manager) HoldResponse(ctx context.Context, req *model.Request, resp *model.Response) model.Outcome {
	it := m.enqueue(model.PendingResponse, req, resp)
	if it == nil {
		return model.Outcome{}
	}
	res := m.wait(ctx, it)
	out := model.Outcome{Note: res.Note}
	if res.Drop {
		out.Verdict = model.VerdictDrop
		return out
	}
	if res.Response != nil && !res.Response.Equal(it.resp) {
		*resp = *res.Response.Clone()
		out.Edited = true
	}
	return out
}

func (m *Manager) enqueue(kind model.PendingKind, req *model.Request, resp *model.Response) *item {
	m.mu.Lock()
	defer m.mu.Unlock()
	if (kind == model.PendingRequest && !m.settings.Request) || (kind == model.PendingResponse && !m.settings.Response) {
		return nil
	}
	m.nextID++
	it := &item{
		sum: model.PendingSummary{
			ID: m.nextID, Kind: kind, Method: req.Method, URL: req.URL, Created: time.Now(),
		},
		req:  req.Clone(),
		resp: resp.Clone(),
		ch:   make(chan model.Resolution, 1),
	}
	if resp != nil {
		it.sum.Status = resp.StatusCode
	}
	if m.timeout > 0 {
		exp := it.sum.Created.Add(m.timeout)
		it.sum.Expires = &exp
	}
	m.items[it.sum.ID] = it
	return it
}

// wait blocks until it is resolved, times out, or ctx is done.
func (m *Manager) wait(ctx context.Context, it *item) model.Resolution {
	var expired <-chan time.Time
	if m.timeout > 0 {
		t := time.NewTimer(m.timeout)
		defer t.Stop()
		expired = t.C
	}
	select {
	case res := <-it.ch:
		return res
	case <-expired:
		if m.take(it) {
			return model.Resolution{Note: "auto-forwarded unmodified after " + m.timeout.String() + " (intercept timeout)"}
		}
	case <-ctx.Done():
		if m.take(it) {
			return model.Resolution{Drop: true, Note: "client disconnected while held"}
		}
	}
	return <-it.ch // Resolve/SetSettings won the race and is sending
}

// take removes it from the queue, reporting whether the caller now owns it.
func (m *Manager) take(it *item) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.items[it.sum.ID] != it {
		return false
	}
	delete(m.items, it.sum.ID)
	return true
}

// Resolve completes a held item. It returns model.ErrPendingGone if the item
// was already resolved, timed out, or its client disconnected.
func (m *Manager) Resolve(id int64, res model.Resolution) error {
	m.mu.Lock()
	it, ok := m.items[id]
	if ok {
		delete(m.items, id)
	}
	m.mu.Unlock()
	if !ok {
		return model.ErrPendingGone
	}
	it.ch <- res
	return nil
}

// List returns the held items, oldest first.
func (m *Manager) List() []model.PendingSummary {
	m.mu.Lock()
	out := make([]model.PendingSummary, 0, len(m.items))
	for _, it := range m.items {
		out = append(out, it.sum)
	}
	m.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Get returns a copy of a held item, or model.ErrPendingGone.
func (m *Manager) Get(id int64) (*model.Pending, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	it, ok := m.items[id]
	if !ok {
		return nil, model.ErrPendingGone
	}
	return &model.Pending{PendingSummary: it.sum, Request: it.req.Clone(), Response: it.resp.Clone()}, nil
}
