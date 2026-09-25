// Package outbound holds everything needed to talk to upstream servers and is
// shared by the proxy engine and the repeater, so both dial, time out,
// validate TLS and report errors in exactly the same way.
package outbound

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Config holds upstream connection settings.
type Config struct {
	DialTimeout   time.Duration
	HeaderTimeout time.Duration

	// InsecureUpstream disables validation of upstream TLS certificates
	// (-insecure-upstream). Validation is on by default.
	InsecureUpstream bool
	// RootCAs overrides the system roots used to validate upstream
	// certificates (nil = system roots).
	RootCAs *x509.CertPool
}

// TLSConfig returns the client TLS settings for upstream connections.
// serverName pins the expected certificate name; empty means "derive it from
// the address being dialed" (net/http does that for hostnames and IPs).
func (c Config) TLSConfig(serverName string) *tls.Config {
	return &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: c.InsecureUpstream, // opt-in via -insecure-upstream
		RootCAs:            c.RootCAs,
	}
}

// NewTransport builds an upstream transport using tlsCfg for https targets.
func (c Config) NewTransport(tlsCfg *tls.Config) *http.Transport {
	return &http.Transport{
		// Never use environment proxies (HTTP_PROXY): we are the proxy.
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: c.DialTimeout, KeepAlive: 30 * time.Second}).DialContext,
		ResponseHeaderTimeout: c.HeaderTimeout,
		TLSHandshakeTimeout:   c.DialTimeout,
		TLSClientConfig:       tlsCfg, // non-nil also keeps upstream on HTTP/1.1
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConnsPerHost:   16,
		// Forward Accept-Encoding untouched and never decompress, so the
		// stored body is exactly what was on the wire.
		DisableCompression: true,
	}
}

// Transport returns a general purpose transport for http:// and https://
// targets (certificate name derived from each request URL).
func (c Config) Transport() *http.Transport { return c.NewTransport(c.TLSConfig("")) }

// hopByHop lists headers that are meaningful only for a single transport-level
// connection and must not be forwarded (RFC 9110 section 7.6.1).
var hopByHop = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// RemoveHopByHop deletes hop-by-hop headers from h, including any header
// named by the Connection header itself.
func RemoveHopByHop(h http.Header) {
	for _, v := range h.Values("Connection") {
		for _, name := range strings.Split(v, ",") {
			if name = strings.TrimSpace(name); name != "" {
				h.Del(name)
			}
		}
	}
	for _, name := range hopByHop {
		h.Del(name)
	}
}

// BuildRequest creates the request sent to a target server. The Host header
// in h, if any, becomes the request's Host (Go ignores it in the header map);
// hop-by-hop headers are stripped. contentLength -1 means unknown (chunked);
// body may be nil.
func BuildRequest(ctx context.Context, method, rawURL string, h http.Header, body io.Reader, contentLength int64) (*http.Request, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("unsupported URL scheme %q (need http or https)", u.Scheme)
	}
	if u.Hostname() == "" {
		return nil, errors.New("URL has no host")
	}
	out, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return nil, err
	}
	hdr := h.Clone()
	if hdr == nil {
		hdr = http.Header{}
	}
	if host := hdr.Get("Host"); host != "" {
		out.Host = host
	}
	hdr.Del("Host")
	RemoveHopByHop(hdr)
	out.Header = hdr
	if body != nil {
		out.ContentLength = contentLength
	}
	if _, ok := hdr["User-Agent"]; !ok {
		// An explicit empty value stops net/http from injecting its own UA.
		hdr.Set("User-Agent", "")
	}
	return out, nil
}

// Capture is an io.Writer that keeps the first max bytes written to it and
// counts everything. It records bodies while they stream; the full body is
// always forwarded regardless of the capture limit.
type Capture struct {
	max   int64
	buf   []byte
	total int64
}

// NewCapture returns a Capture keeping at most max bytes.
func NewCapture(max int64) *Capture { return &Capture{max: max} }

// Write implements io.Writer; it never fails.
func (c *Capture) Write(p []byte) (int, error) {
	n := len(p)
	c.total += int64(n)
	if room := c.max - int64(len(c.buf)); room > 0 {
		if int64(len(p)) > room {
			p = p[:room]
		}
		c.buf = append(c.buf, p...)
	}
	return n, nil
}

// Bytes returns the captured prefix.
func (c *Capture) Bytes() []byte { return c.buf }

// Total returns the number of bytes written, captured or not.
func (c *Capture) Total() int64 { return c.total }

// ReadUpTo reads at most max bytes from r. whole reports whether r hit EOF
// within that limit; when it is false, buf holds the first max+1 bytes read
// and the caller must stitch them back in front of r to keep streaming.
func ReadUpTo(r io.Reader, max int64) (buf []byte, whole bool, err error) {
	buf, err = io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return buf, false, err
	}
	return buf, int64(len(buf)) <= max, nil
}

// Classify maps a transport error to an HTTP status and a readable message.
// Status 0 means the client went away and nobody can be answered.
func Classify(err error, host string) (int, string) {
	var (
		netErr  net.Error
		dnsErr  *net.DNSError
		opErr   *net.OpError
		certErr *tls.CertificateVerificationError
		recErr  tls.RecordHeaderError
	)
	// Deliberately no syscall.ECONNREFUSED check: errno values differ between
	// Windows and Linux, so the dial error text is used instead.
	switch {
	case errors.Is(err, context.Canceled):
		return 0, "client closed the connection"
	case errors.As(err, &certErr):
		return http.StatusBadGateway, fmt.Sprintf("the certificate presented by %s failed validation: %v (start proxyscope with -insecure-upstream to accept invalid upstream certificates)", host, strings.TrimRight(certErr.Err.Error(), ": "))
	case errors.As(err, &recErr):
		return http.StatusBadGateway, fmt.Sprintf("%s does not speak TLS on this port", host)
	case errors.As(err, &dnsErr):
		return http.StatusBadGateway, fmt.Sprintf("cannot resolve host %q: %s", dnsErr.Name, dnsErr.Err)
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netErr) && netErr.Timeout():
		return http.StatusGatewayTimeout, fmt.Sprintf("timed out talking to %s: %v", host, err)
	case errors.As(err, &opErr) && opErr.Op == "dial":
		return http.StatusBadGateway, fmt.Sprintf("could not connect to %s: %v", host, opErr.Err)
	default:
		return http.StatusBadGateway, fmt.Sprintf("error talking to %s: %v", host, err)
	}
}

// SyncContentLength makes a header set describe a body of bodyLen bytes as it
// is actually sent: an existing (possibly stale, after an edit) Content-Length
// is corrected, a missing one is added for non-empty bodies, and it is removed
// when there is no body. Used for the stored copy of edited/replayed requests.
func SyncContentLength(h http.Header, bodyLen int) {
	switch {
	case bodyLen > 0:
		h.Set("Content-Length", strconv.Itoa(bodyLen))
	default:
		h.Del("Content-Length")
	}
}
