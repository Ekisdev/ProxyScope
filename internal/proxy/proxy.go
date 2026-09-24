// Package proxy implements the plain-HTTP intercepting proxy engine.
//
// Phase 1 scope: HTTP/1.1 forward proxying with capture of every exchange.
// HTTPS (CONNECT) and protocol upgrades are answered with a readable 501.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"proxyscope/internal/model"
)

// Sink receives every completed exchange. The storage layer implements it;
// keeping it an interface lets later phases add hooks without touching storage.
type Sink interface {
	Save(ctx context.Context, ex *model.Exchange) error
}

// Config holds proxy engine settings.
type Config struct {
	Addr          string
	MaxBodyBytes  int64
	DialTimeout   time.Duration
	HeaderTimeout time.Duration
}

// Proxy is an HTTP forward proxy that records the traffic it relays.
type Proxy struct {
	cfg       Config
	sink      Sink
	log       *slog.Logger
	transport *http.Transport
	server    *http.Server

	// Set in ListenAndServe before serving; used for self-loop detection.
	selfHost string
	selfPort string
}

// New creates a Proxy. It does not start listening.
func New(cfg Config, sink Sink, log *slog.Logger) *Proxy {
	p := &Proxy{cfg: cfg, sink: sink, log: log}
	p.transport = &http.Transport{
		// Never use environment proxies (HTTP_PROXY): we are the proxy.
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: cfg.DialTimeout, KeepAlive: 30 * time.Second}).DialContext,
		ResponseHeaderTimeout: cfg.HeaderTimeout,
		TLSHandshakeTimeout:   cfg.DialTimeout,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConnsPerHost:   16,
		// Forward Accept-Encoding untouched and never decompress, so the
		// stored body is exactly what was on the wire.
		DisableCompression: true,
	}
	p.server = &http.Server{
		Handler:           p,
		ReadHeaderTimeout: 30 * time.Second,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelDebug),
	}
	return p
}

// ListenAndServe listens on the configured address and serves until Shutdown.
// It returns nil after a clean shutdown.
func (p *Proxy) ListenAndServe() error {
	ln, err := net.Listen("tcp", p.cfg.Addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", p.cfg.Addr, err)
	}
	p.selfHost, p.selfPort, _ = net.SplitHostPort(ln.Addr().String())
	p.log.Info("proxy listening", "addr", ln.Addr().String())
	if err := p.server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Shutdown gracefully stops the proxy.
func (p *Proxy) Shutdown(ctx context.Context) error {
	err := p.server.Shutdown(ctx)
	p.transport.CloseIdleConnections()
	return err
}

// ServeHTTP implements http.Handler.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodConnect:
		p.rejectConnect(w, r)
	case !r.URL.IsAbs() || r.URL.Host == "":
		plainError(w, http.StatusBadRequest,
			"proxyscope is an HTTP proxy, not a web server.\n"+
				"Configure your browser/client to use it as an HTTP proxy and request an http:// URL.")
	case r.URL.Scheme != "http":
		plainError(w, http.StatusBadRequest, fmt.Sprintf("unsupported scheme %q: only http is supported in Phase 1", r.URL.Scheme))
	case p.isSelf(r.URL):
		plainError(w, http.StatusLoopDetected, "request targets the proxy itself; refusing to forward it to avoid a loop")
	case isUpgrade(r):
		plainError(w, http.StatusNotImplemented, "protocol upgrades (e.g. WebSocket) are not supported in Phase 1")
	default:
		p.forward(w, r)
	}
}

// rejectConnect answers HTTPS tunnel requests. TLS interception is Phase 2;
// the attempt is still recorded so it shows up in the history.
func (p *Proxy) rejectConnect(w http.ResponseWriter, r *http.Request) {
	const msg = "HTTPS (CONNECT) is not supported yet: proxyscope Phase 1 handles plain HTTP only"
	ex := &model.Exchange{
		Timestamp:  time.Now(),
		Method:     r.Method,
		URL:        r.Host,
		Host:       r.Host,
		Path:       "",
		Proto:      r.Proto,
		ReqHeaders: r.Header.Clone(),
		StatusCode: http.StatusNotImplemented,
		Error:      msg,
	}
	plainError(w, http.StatusNotImplemented, msg)
	p.save(ex)
}

// forward relays one request to the target server and records the exchange.
func (p *Proxy) forward(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ex := &model.Exchange{
		Timestamp:  start,
		Method:     r.Method,
		URL:        r.URL.String(),
		Host:       r.URL.Host,
		Path:       r.URL.RequestURI(),
		Proto:      r.Proto,
		ReqHeaders: r.Header.Clone(),
	}
	reqCap := newCapture(p.cfg.MaxBodyBytes)
	respCap := newCapture(p.cfg.MaxBodyBytes)
	defer func() {
		ex.ReqBody, ex.ReqBodySize = reqCap.buf, reqCap.total
		ex.RespBody, ex.RespBodySize = respCap.buf, respCap.total
		ex.Duration = time.Since(start)
		p.save(ex)
	}()

	out, err := p.buildOutbound(r, reqCap)
	if err != nil {
		ex.StatusCode, ex.Error = http.StatusBadRequest, err.Error()
		plainError(w, ex.StatusCode, "invalid request: "+err.Error())
		return
	}

	resp, err := p.transport.RoundTrip(out)
	if err != nil {
		status, msg := classify(err, r.URL.Host)
		ex.StatusCode, ex.Error = status, msg
		if errors.Is(err, context.Canceled) {
			// Client went away; nobody to answer.
			ex.StatusCode = 0
			p.log.Debug("client cancelled request", "url", ex.URL)
			return
		}
		p.log.Warn("upstream request failed", "method", r.Method, "url", ex.URL, "err", err)
		plainError(w, status, msg)
		return
	}
	defer resp.Body.Close()

	ex.StatusCode = resp.StatusCode
	ex.RespHeaders = resp.Header.Clone()

	h := w.Header()
	for k, vv := range resp.Header {
		h[k] = append([]string(nil), vv...)
	}
	removeHopByHop(h)
	w.WriteHeader(resp.StatusCode)

	upstreamErr, err := copyBody(w, resp, respCap)
	if err != nil {
		ex.Error = "relaying response body: " + err.Error()
		p.log.Warn("relay interrupted", "url", ex.URL, "err", err)
		if upstreamErr {
			// Headers are already sent; abort the connection so the client
			// sees a truncated response instead of a falsely complete one.
			// The deferred save still runs while the panic unwinds.
			panic(http.ErrAbortHandler)
		}
	}
}

// buildOutbound creates the request sent to the target server. The request
// body is teed into reqCap as it streams.
func (p *Proxy) buildOutbound(r *http.Request, reqCap *capture) (*http.Request, error) {
	var body io.Reader
	if r.ContentLength != 0 && r.Body != nil && r.Body != http.NoBody {
		body = io.TeeReader(r.Body, reqCap)
	}
	out, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), body)
	if err != nil {
		return nil, err
	}
	out.Host = r.Host
	out.Header = r.Header.Clone()
	removeHopByHop(out.Header)
	if body != nil {
		out.ContentLength = r.ContentLength // -1 means unknown: sent chunked
	}
	if _, ok := out.Header["User-Agent"]; !ok {
		// An explicit empty value stops net/http from injecting its own UA.
		out.Header.Set("User-Agent", "")
	}
	return out, nil
}

// copyBody streams resp.Body to w while recording it. The bool result tells
// whether a returned error came from the upstream side (true) or the client (false).
func copyBody(w http.ResponseWriter, resp *http.Response, rec *capture) (upstream bool, err error) {
	rc := http.NewResponseController(w)
	flush := resp.ContentLength < 0 // unknown length: likely streaming, don't buffer
	buf := make([]byte, 32*1024)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			rec.Write(buf[:n])
			if _, werr := w.Write(buf[:n]); werr != nil {
				return false, werr
			}
			if flush {
				_ = rc.Flush()
			}
		}
		if rerr == io.EOF {
			return false, nil
		}
		if rerr != nil {
			return true, rerr
		}
	}
}

// save records ex. It never fails the request: errors are only logged.
func (p *Proxy) save(ex *model.Exchange) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := p.sink.Save(ctx, ex); err != nil {
		p.log.Error("saving exchange failed", "url", ex.URL, "err", err)
		return
	}
	p.log.Info("exchange", "id", ex.ID, "method", ex.Method, "url", ex.URL, "status", ex.StatusCode, "dur", ex.Duration.Round(time.Millisecond))
}

// isSelf reports whether u points at this proxy's own listener.
func (p *Proxy) isSelf(u *url.URL) bool {
	port := u.Port()
	if port == "" {
		port = "80"
	}
	if port != p.selfPort {
		return false
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") || host == p.selfHost {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsLoopback() || ip.IsUnspecified())
}

// classify maps a transport error to an HTTP status and a readable message.
func classify(err error, host string) (int, string) {
	var (
		netErr net.Error
		dnsErr *net.DNSError
		opErr  *net.OpError
	)
	// Deliberately no syscall.ECONNREFUSED check: errno values differ between
	// Windows and Linux, so the dial error text is used instead.
	switch {
	case errors.Is(err, context.Canceled):
		return 0, "client closed the connection"
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

func plainError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	fmt.Fprintf(w, "proxyscope: %s\n", msg)
}
