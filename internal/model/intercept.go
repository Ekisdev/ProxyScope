package model

import (
	"bytes"
	"errors"
	"net/http"
	"time"
)

// ErrPendingGone is returned when an intercept item no longer exists: it was
// already resolved, timed out, or its client disconnected.
var ErrPendingGone = errors.New("pending item no longer exists (already resolved, timed out or client disconnected)")

// ErrInvalidRequest wraps problems with a request the user composed (bad URL,
// method, ...), as opposed to network failures, which are results.
var ErrInvalidRequest = errors.New("invalid request")

// Request is a request as held by the intercept queue and sent by the
// repeater. Header carries the Host header explicitly (as "Host") so it can be
// shown and edited; outbound.BuildRequest turns it into the request Host.
type Request struct {
	Method string
	URL    string // absolute http:// or https:// URL
	Header http.Header
	Body   []byte
}

// Clone returns a deep copy.
func (r *Request) Clone() *Request {
	if r == nil {
		return nil
	}
	return &Request{Method: r.Method, URL: r.URL, Header: r.Header.Clone(), Body: bytes.Clone(r.Body)}
}

// Equal reports whether two requests are identical.
func (r *Request) Equal(o *Request) bool {
	return r.Method == o.Method && r.URL == o.URL && headersEqual(r.Header, o.Header) && bytes.Equal(r.Body, o.Body)
}

// Response is a response as held by the intercept queue. Body is the raw body
// as received (possibly compressed, see Header "Content-Encoding").
type Response struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

// Clone returns a deep copy.
func (r *Response) Clone() *Response {
	if r == nil {
		return nil
	}
	return &Response{StatusCode: r.StatusCode, Header: r.Header.Clone(), Body: bytes.Clone(r.Body)}
}

// Equal reports whether two responses are identical.
func (r *Response) Equal(o *Response) bool {
	return r.StatusCode == o.StatusCode && headersEqual(r.Header, o.Header) && bytes.Equal(r.Body, o.Body)
}

func headersEqual(a, b http.Header) bool {
	if len(a) != len(b) {
		return false
	}
	for k, av := range a {
		bv, ok := b[k]
		if !ok || len(av) != len(bv) {
			return false
		}
		for i := range av {
			if av[i] != bv[i] {
				return false
			}
		}
	}
	return true
}

// Verdict is what happens to a held message.
type Verdict int

const (
	VerdictForward Verdict = iota // continue (possibly edited)
	VerdictDrop                   // answer the client with a clean error instead
)

// Outcome is the result of holding a message in the intercept queue.
type Outcome struct {
	Verdict Verdict
	Edited  bool   // the held message was modified in place
	Note    string // non-error annotation for the history, e.g. auto-forward
}

// InterceptSettings are the two independent pause points.
type InterceptSettings struct {
	Request  bool `json:"request"`
	Response bool `json:"response"`
}

// PendingKind says at which pause point an item is held.
type PendingKind string

const (
	PendingRequest  PendingKind = "request"
	PendingResponse PendingKind = "response"
)

// PendingSummary is the light list entry of a held message.
type PendingSummary struct {
	ID      int64       `json:"id"`
	Kind    PendingKind `json:"kind"`
	Method  string      `json:"method"`
	URL     string      `json:"url"`
	Status  int         `json:"status,omitempty"` // response items only
	Created time.Time   `json:"created"`
	Expires *time.Time  `json:"expires,omitempty"` // auto-forward deadline, nil = none
}

// Pending is a held message with everything needed to edit it.
type Pending struct {
	PendingSummary
	Request  *Request  // for response items: the request that produced it (context)
	Response *Response // response items only
}

// Resolution is the user's decision on a held message. Request/Response carry
// the (possibly edited) message to forward; when nil the original goes as-is.
type Resolution struct {
	Drop     bool
	Request  *Request
	Response *Response
	Note     string // set by the queue itself (e.g. released because intercept was turned off)
}
