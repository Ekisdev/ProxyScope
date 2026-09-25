package ui

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"unicode/utf8"
)

const (
	maxDecoded  = 8 << 20 // decompression cap, guards against zip bombs
	maxTextView = 1 << 20 // max characters of text sent to the browser
	maxHexView  = 64 << 10
)

// bodyView is how a stored body is presented to the browser.
type bodyView struct {
	Size        int64  `json:"size"`                  // real size on the wire
	Stored      int    `json:"stored"`                // bytes kept in the database
	Truncated   bool   `json:"truncated"`             // stored < size
	Encoding    string `json:"encoding"`              // "text" or "hex"
	DecodedFrom string `json:"decodedFrom,omitempty"` // e.g. "gzip"
	Clipped     bool   `json:"clipped,omitempty"`     // content cut for display only
	Content     string `json:"content"`
	// Editable is set only for bodies offered in an edit form: valid UTF-8 text
	// that is complete (not truncated, clipped or partially decompressed).
	Editable bool `json:"editable,omitempty"`
}

// renderBody turns raw stored bytes into something displayable: it undoes
// gzip/deflate Content-Encoding when possible, then shows valid UTF-8 as text
// and everything else as a hex dump.
func renderBody(h http.Header, body []byte, size int64) bodyView {
	v := bodyView{
		Size:      size,
		Stored:    len(body),
		Truncated: size > int64(len(body)),
		Encoding:  "text",
	}
	if len(body) == 0 {
		return v
	}
	data, from := decodeForDisplay(h, body)
	v.DecodedFrom = from
	if text, ok := asText(data, v.Truncated || v.DecodedFrom != ""); ok {
		if len(text) > maxTextView {
			text, v.Clipped = text[:maxTextView], true
			text = strings.ToValidUTF8(text, "")
		}
		v.Content = text
		return v
	}
	v.Encoding = "hex"
	v.Content, v.Clipped = hexView(data)
	return v
}

// hexView renders data as a hex dump (offset/hex/ASCII), capped at
// maxHexView bytes for display. Shared by renderBody (binary HTTP bodies)
// and the relay chunk view (internal/ui/relay.go), which is always raw
// bytes with no text/binary detection to do.
func hexView(data []byte) (content string, clipped bool) {
	if len(data) > maxHexView {
		data, clipped = data[:maxHexView], true
	}
	return hex.Dump(data), clipped
}

// decode undoes a single Content-Encoding. A partially readable (truncated)
// stream yields whatever could be decoded.
func decode(enc string, body []byte) ([]byte, bool) {
	var r io.Reader
	var err error
	switch enc {
	case "gzip", "x-gzip":
		r, err = gzip.NewReader(bytes.NewReader(body))
	case "deflate":
		// HTTP "deflate" is zlib-wrapped, but some servers send raw deflate.
		if r, err = zlib.NewReader(bytes.NewReader(body)); err != nil {
			r, err = flate.NewReader(bytes.NewReader(body)), nil
		}
	default:
		return nil, false // br, zstd, ...: shown as-is
	}
	if err != nil {
		return nil, false
	}
	out, _ := io.ReadAll(io.LimitReader(r, maxDecoded)) // partial output is fine
	return out, len(out) > 0
}

// asText reports whether data is displayable text. When the data may have been
// cut mid-character (truncated/decoded partially) up to 3 trailing bytes of an
// incomplete UTF-8 sequence are tolerated.
func asText(data []byte, lenient bool) (string, bool) {
	if bytes.IndexByte(data, 0) >= 0 {
		return "", false
	}
	if utf8.Valid(data) {
		return string(data), true
	}
	if lenient {
		for i := 1; i <= 3 && i < len(data); i++ {
			if utf8.Valid(data[:len(data)-i]) {
				return string(data[:len(data)-i]), true
			}
		}
	}
	return "", false
}

// decodeForDisplay returns the body as a person would read it: decompressed
// when Content-Encoding is gzip/deflate and decoding works, together with the
// encoding that was undone ("" if none). Otherwise the raw bytes.
func decodeForDisplay(h http.Header, body []byte) (data []byte, decodedFrom string) {
	if enc := strings.ToLower(strings.TrimSpace(h.Get("Content-Encoding"))); enc != "" && len(body) > 0 {
		if dec, ok := decode(enc, body); ok {
			return dec, enc
		}
	}
	return body, ""
}
