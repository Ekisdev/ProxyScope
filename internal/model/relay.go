package model

import (
	"bytes"
	"time"
)

// Relay types (Phase 5). Like the match & replace types, these live here so
// ui and other packages never need to import internal/relay directly.
// model.Verdict/Outcome/ErrPendingGone (defined in intercept.go) are already
// payload-agnostic and are reused as-is by the relay's hold queue; only the
// held payload itself (Chunk, below) and the pending/resolution shapes
// around it are relay-specific, because a raw byte chunk has no method,
// URL or status the way an HTTP Request/Response does.

// RelayProtocol is the transport a relay target listens on.
type RelayProtocol string

const (
	RelayTCP RelayProtocol = "tcp"
	RelayUDP RelayProtocol = "udp"
)

// RelayDirection says which way a chunk is travelling.
type RelayDirection string

const (
	RelayUp   RelayDirection = "up"   // client -> upstream
	RelayDown RelayDirection = "down" // upstream -> client
)

// RelayTarget describes one configured relay target (name, protocol,
// listen/upstream addresses). internal/relay aliases this as Target so its
// own code can spell it unqualified, exactly like the match & replace rule
// types; ui references it directly for the status listing, without
// importing internal/relay.
type RelayTarget struct {
	Name     string        `json:"name"`
	Protocol RelayProtocol `json:"protocol"`
	Listen   string        `json:"listen"`
	Upstream string        `json:"upstream"`
}

// Chunk is a raw byte chunk as held by the relay's intercept queue for
// editing (as hex) before it is forwarded. There is no message framing at
// this layer (unlike HTTP's Content-Length/chunked), so a "chunk" is
// whatever one read from the wire produced.
type Chunk struct {
	Data []byte
}

// Clone returns a deep copy.
func (c *Chunk) Clone() *Chunk {
	if c == nil {
		return nil
	}
	return &Chunk{Data: bytes.Clone(c.Data)}
}

// Equal reports whether two chunks hold the same bytes.
func (c *Chunk) Equal(o *Chunk) bool { return bytes.Equal(c.Data, o.Data) }

// RelaySettings are the independent per-direction pause-point toggles for
// one relay target: the byte-stream equivalent of InterceptSettings.
type RelaySettings struct {
	Up   bool `json:"up"`
	Down bool `json:"down"`
}

// RelayPendingSummary is the light list entry of a held relay chunk.
type RelayPendingSummary struct {
	ID        int64          `json:"id"`
	Target    string         `json:"target"`
	SessionID int64          `json:"sessionId"`
	Direction RelayDirection `json:"direction"`
	Size      int            `json:"size"`
	Created   time.Time      `json:"created"`
	Expires   *time.Time     `json:"expires,omitempty"` // auto-forward deadline, nil = none
}

// RelayPending is a held chunk with everything needed to edit it.
type RelayPending struct {
	RelayPendingSummary
	Chunk *Chunk
}

// RelayResolution is the user's decision on a held chunk. Chunk carries the
// (possibly edited) bytes to forward; nil means forward the original as-is.
type RelayResolution struct {
	Drop  bool
	Chunk *Chunk
	Note  string // set by the queue itself (e.g. released because intercept was turned off)
}

// RelaySession is one relayed TCP connection or UDP client grouping, as
// stored. ClosedAt is the zero Time while the session is still open.
type RelaySession struct {
	ID           int64
	Target       string // configured relay target name
	Protocol     RelayProtocol
	ClientAddr   string // client ip:port; a UDP session is grouped by this
	UpstreamAddr string // host:port this session was relayed to
	OpenedAt     time.Time
	ClosedAt     time.Time // zero value = still open
	BytesUp      int64     // real total bytes seen, client -> upstream (>= captured)
	BytesDown    int64     // real total bytes seen, upstream -> client (>= captured)
	Error        string    // set if the session ended abnormally (dial failure, ...)
}

// RelaySessionSummary is the lightweight row shown in the session list.
type RelaySessionSummary struct {
	ID           int64      `json:"id"`
	Target       string     `json:"target"`
	Protocol     string     `json:"protocol"`
	ClientAddr   string     `json:"clientAddr"`
	UpstreamAddr string     `json:"upstreamAddr"`
	OpenedAt     time.Time  `json:"openedAt"`
	ClosedAt     *time.Time `json:"closedAt,omitempty"`
	BytesUp      int64      `json:"bytesUp"`
	BytesDown    int64      `json:"bytesDown"`
	Error        string     `json:"error,omitempty"`
}

// RelayChunk is one captured chunk, as stored.
type RelayChunk struct {
	ID        int64
	SessionID int64
	Seq       int64 // capture order within the session; both directions share one sequence
	Direction RelayDirection
	Timestamp time.Time
	Data      []byte // possibly capped, see DataSize
	DataSize  int64  // real size on the wire
	Edited    bool   // modified via relay intercept
	Note      string // e.g. "not intercepted: session capture cap reached"
}

// DataTruncated reports whether Data holds fewer bytes than were captured.
func (c *RelayChunk) DataTruncated() bool { return c.DataSize > int64(len(c.Data)) }
