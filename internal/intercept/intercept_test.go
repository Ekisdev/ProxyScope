package intercept

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"proxyscope/internal/model"
)

func req(path string) *model.Request {
	return &model.Request{Method: "GET", URL: "http://example.com" + path, Header: http.Header{"X-A": {"1"}}}
}

func waitPending(t *testing.T, m *Manager, n int) []model.PendingSummary {
	t.Helper()
	for i := 0; i < 200; i++ {
		if l := m.List(); len(l) == n {
			return l
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("expected %d pending items, have %d", n, len(m.List()))
	return nil
}

func TestOffByDefaultPassesThrough(t *testing.T) {
	m := New(time.Second)
	if out := m.HoldRequest(context.Background(), req("/")); out.Verdict != model.VerdictForward || out.Edited {
		t.Fatalf("outcome = %+v", out)
	}
	if len(m.List()) != 0 {
		t.Fatal("nothing should be queued while intercept is off")
	}
}

func TestEditAndForward(t *testing.T) {
	m := New(5 * time.Second)
	m.SetSettings(model.InterceptSettings{Request: true})
	r := req("/a")
	done := make(chan model.Outcome)
	go func() { done <- m.HoldRequest(context.Background(), r) }()

	l := waitPending(t, m, 1)
	p, _ := m.Get(l[0].ID)
	edited := p.Request.Clone()
	edited.Method = "POST"
	edited.Body = []byte("x=1")
	if err := m.Resolve(l[0].ID, model.Resolution{Request: edited}); err != nil {
		t.Fatal(err)
	}
	out := <-done
	if !out.Edited || r.Method != "POST" || string(r.Body) != "x=1" {
		t.Fatalf("edit not applied: %+v %+v", out, r)
	}
	if err := m.Resolve(l[0].ID, model.Resolution{}); err != model.ErrPendingGone {
		t.Fatalf("second resolve = %v, want ErrPendingGone", err)
	}
}

func TestUnchangedEditIsNotReportedAsEdited(t *testing.T) {
	m := New(5 * time.Second)
	m.SetSettings(model.InterceptSettings{Request: true})
	done := make(chan model.Outcome)
	go func() { done <- m.HoldRequest(context.Background(), req("/")) }()
	l := waitPending(t, m, 1)
	p, _ := m.Get(l[0].ID)
	m.Resolve(l[0].ID, model.Resolution{Request: p.Request})
	if out := <-done; out.Edited {
		t.Fatal("identical request must not count as edited")
	}
}

func TestDrop(t *testing.T) {
	m := New(5 * time.Second)
	m.SetSettings(model.InterceptSettings{Request: true})
	done := make(chan model.Outcome)
	go func() { done <- m.HoldRequest(context.Background(), req("/")) }()
	l := waitPending(t, m, 1)
	m.Resolve(l[0].ID, model.Resolution{Drop: true})
	if out := <-done; out.Verdict != model.VerdictDrop {
		t.Fatalf("outcome = %+v", out)
	}
}

func TestManyHeldRequestsResolveIndependently(t *testing.T) {
	m := New(10 * time.Second)
	m.SetSettings(model.InterceptSettings{Request: true})
	const n = 25
	var wg sync.WaitGroup
	verdicts := make([]model.Verdict, n) // indexed by request number
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			verdicts[i] = m.HoldRequest(context.Background(), req("/"+strconv.Itoa(i))).Verdict
		}()
	}
	l := waitPending(t, m, n)
	// Resolve newest first, dropping the even-numbered requests: every held
	// request must get exactly its own verdict and block only itself.
	for i := len(l) - 1; i >= 0; i-- {
		p, _ := m.Get(l[i].ID)
		num, _ := strconv.Atoi(strings.TrimPrefix(p.Request.URL, "http://example.com/"))
		if err := m.Resolve(l[i].ID, model.Resolution{Drop: num%2 == 0}); err != nil {
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
			t.Fatalf("request %d: verdict %d, want %d", i, v, want)
		}
	}
	if len(m.List()) != 0 {
		t.Fatal("queue should be empty")
	}
}

func TestTimeoutAutoForwards(t *testing.T) {
	m := New(50 * time.Millisecond)
	m.SetSettings(model.InterceptSettings{Request: true})
	start := time.Now()
	out := m.HoldRequest(context.Background(), req("/"))
	if out.Verdict != model.VerdictForward || out.Edited || out.Note == "" || time.Since(start) < 40*time.Millisecond {
		t.Fatalf("outcome = %+v after %v", out, time.Since(start))
	}
	if len(m.List()) != 0 {
		t.Fatal("timed-out item must leave the queue")
	}
}

func TestClientDisconnectRemovesItem(t *testing.T) {
	m := New(10 * time.Second)
	m.SetSettings(model.InterceptSettings{Request: true})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan model.Outcome)
	go func() { done <- m.HoldRequest(ctx, req("/")) }()
	waitPending(t, m, 1)
	cancel()
	if out := <-done; out.Verdict != model.VerdictDrop {
		t.Fatalf("outcome = %+v", out)
	}
	waitPending(t, m, 0)
}

func TestTurningOffReleasesHeldItems(t *testing.T) {
	m := New(10 * time.Second)
	m.SetSettings(model.InterceptSettings{Request: true, Response: true})
	done := make(chan model.Outcome, 2)
	go func() { done <- m.HoldRequest(context.Background(), req("/1")) }()
	go func() {
		done <- m.HoldResponse(context.Background(), req("/2"), &model.Response{StatusCode: 200, Header: http.Header{}})
	}()
	waitPending(t, m, 2)
	m.SetSettings(model.InterceptSettings{Request: false, Response: true}) // only requests released
	out := <-done
	if out.Verdict != model.VerdictForward || out.Note == "" {
		t.Fatalf("outcome = %+v", out)
	}
	if l := waitPending(t, m, 1); l[0].Kind != model.PendingResponse {
		t.Fatalf("remaining item = %+v", l[0])
	}
	m.SetSettings(model.InterceptSettings{})
	<-done
}

func TestResponseEdit(t *testing.T) {
	m := New(5 * time.Second)
	m.SetSettings(model.InterceptSettings{Response: true})
	resp := &model.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/plain"}}, Body: []byte("hi")}
	done := make(chan model.Outcome)
	go func() { done <- m.HoldResponse(context.Background(), req("/"), resp) }()
	l := waitPending(t, m, 1)
	p, _ := m.Get(l[0].ID)
	if p.Response == nil || p.Request == nil || l[0].Status != 200 {
		t.Fatalf("pending = %+v", p)
	}
	e := p.Response.Clone()
	e.StatusCode, e.Body = 418, []byte("teapot")
	m.Resolve(l[0].ID, model.Resolution{Response: e})
	out := <-done
	if !out.Edited || resp.StatusCode != 418 || string(resp.Body) != "teapot" {
		t.Fatalf("edit not applied: %+v %+v", out, resp)
	}
}
