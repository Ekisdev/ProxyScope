// Package model defines the data types shared by every proxyscope package.
// It has no dependencies on other internal packages.
package model

import (
	"errors"
	"net/http"
	"time"
)

// ErrNotFound is returned by storage when an exchange id does not exist.
var ErrNotFound = errors.New("exchange not found")

// Exchange is one captured request together with its response (or the error
// that prevented a response).
type Exchange struct {
	ID        int64
	Timestamp time.Time     // when the request was received by the proxy
	Duration  time.Duration // request received -> response body fully relayed

	// Request, as sent by the client.
	Method     string
	URL        string // absolute URL, e.g. http://example.com/a?b=1
	Host       string // host[:port] of the target
	Path       string // path + query, e.g. /a?b=1
	Proto      string // e.g. HTTP/1.1
	ReqHeaders http.Header
	ReqBody    []byte // possibly truncated, see ReqBodySize
	// ReqBodySize is the real number of body bytes seen on the wire; it is
	// larger than len(ReqBody) when the capture was truncated.
	ReqBodySize int64

	// Response, as returned to the client. StatusCode is 0 when the client
	// disconnected before any response was produced.
	StatusCode   int
	RespHeaders  http.Header
	RespBody     []byte // possibly truncated, see RespBodySize
	RespBodySize int64

	// Error is a human readable description of what went wrong (upstream
	// unreachable, timeout, ...). Empty on success.
	Error string
}

// ReqBodyTruncated reports whether ReqBody holds fewer bytes than were sent.
func (e *Exchange) ReqBodyTruncated() bool { return e.ReqBodySize > int64(len(e.ReqBody)) }

// RespBodyTruncated reports whether RespBody holds fewer bytes than were received.
func (e *Exchange) RespBodyTruncated() bool { return e.RespBodySize > int64(len(e.RespBody)) }

// Summary is the lightweight row shown in the history list (no headers/bodies).
type Summary struct {
	ID           int64     `json:"id"`
	Timestamp    time.Time `json:"timestamp"`
	DurationMs   float64   `json:"durationMs"`
	Method       string    `json:"method"`
	URL          string    `json:"url"`
	Host         string    `json:"host"`
	Path         string    `json:"path"`
	StatusCode   int       `json:"status"`
	RespBodySize int64     `json:"size"`
	Error        string    `json:"error,omitempty"`
}
