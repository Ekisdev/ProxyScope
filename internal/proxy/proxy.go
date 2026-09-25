// Package proxy implements the intercepting proxy engine.
//
// Plain HTTP requests are forwarded and recorded (Phase 1). HTTPS is handled
// by terminating TLS on CONNECT tunnels with per-host certificates from a
// local CA and relaying the decrypted HTTP/1.1 stream through the same
// forwarding path (Phase 2, see tunnel.go). Both share forward(), which also
// hosts the two pause points (Phase 3 live intercept, Phase 4 match &
// replace rules): after the request is fully received and before it is sent
// upstream, and after the response is fully received and before it is sent
// to the client. At each point rules run first (automatically, whether or
// not intercept is on), then intercept, if enabled, holds the
// already-rule-transformed message for a human. Protocol upgrades
// (WebSocket) are answered with a readable 501.
package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"proxyscope/internal/model"
	"proxyscope/internal/outbound"
)

// Sink receives every completed exchange. The storage layer implements it;
// keeping it an interface lets later phases add hooks without touching storage.
type Sink interface {
	Save(ctx context.Context, ex *model.Exchange) error
}

// Interceptor is the live-intercept pause point, implemented by
// intercept.Manager. A nil Interceptor means nothing is ever held. The Hold
// methods block until the user resolves the message (or a timeout/disconnect
// releases it), applying any edits to their argument in place.
type Interceptor interface {
	RequestEnabled() bool
	ResponseEnabled() bool
	HoldRequest(ctx context.Context, req *model.Request) model.Outcome
	HoldResponse(ctx context.Context, req *model.Request, resp *model.Response) model.Outcome
}

// RuleEngine is the match & replace pause point, implemented by
// rules.Engine. A nil RuleEngine means no rules ever run. Unlike Interceptor
// it never blocks: Apply* runs synchronously and returns the ids of the
// rules that fired, mutating req/resp in place. It runs whether or not live
// intercept is enabled, and (at each pause point) before the Interceptor
// sees the message, so a human reviewing a held item sees the
// already-rule-transformed version, not the original.
type RuleEngine interface {
	NeedsRequestBody() bool
	NeedsResponseBody() bool
	ApplyRequest(req *model.Request, bodyAvailable bool) []string
	ApplyResponse(req *model.Request, resp *model.Response, bodyAvailable bool) []string
}

// Config holds proxy engine settings.
type Config struct {
	Addr         string
	MaxBodyBytes int64
	Outbound     outbound.Config // dialing, timeouts and upstream TLS validation
}

// CertIssuer provides the certificates presented to clients on intercepted
// TLS connections. Implemented by ca.Authority.
type CertIssuer interface {
	// CertificateFor returns a certificate valid for name (DNS name or IP),
	// or an error if name is not acceptable.
	CertificateFor(name string) (*tls.Certificate, error)
}

// Proxy is an HTTP forward proxy that records the traffic it relays.
type Proxy struct {
	cfg       Config
	out       outbound.Config
	sink      Sink
	issuer    CertIssuer
	icpt      Interceptor // may be nil
	re        RuleEngine  // may be nil
	log       *slog.Logger
	transport *http.Transport // plain HTTP upstreams
	server    *http.Server

	// Set in ListenAndServe before serving; used for self-loop detection.
	selfHost string
	selfPort string

	// Active TLS tunnels, so Shutdown can close them (hijacked connections
	// are not tracked by http.Server).
	tunnelMu sync.Mutex
	tunnels  map[*http.Server]struct{}
}

// New creates a Proxy. icpt and re may each be nil (intercept/rules
// unavailable). It does not start listening.
func New(cfg Config, sink Sink, issuer CertIssuer, icpt Interceptor, re RuleEngine, log *slog.Logger) *Proxy {
	p := &Proxy{cfg: cfg, out: cfg.Outbound, sink: sink, issuer: issuer, icpt: icpt, re: re, log: log, tunnels: map[*http.Server]struct{}{}}
	p.transport = p.out.Transport()
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
	p.tunnelMu.Lock()
	for srv := range p.tunnels {
		srv.Close()
	}
	p.tunnelMu.Unlock()
	return err
}

// ServeHTTP implements http.Handler.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodConnect:
		p.handleConnect(w, r)
	case !r.URL.IsAbs() || r.URL.Host == "":
		plainError(w, http.StatusBadRequest,
			"proxyscope is an HTTP proxy, not a web server.\n"+
				"Configure your browser/client to use it as an HTTP proxy and request an http:// or https:// URL.")
	case r.URL.Scheme != "http":
		// https:// requests must arrive through a CONNECT tunnel.
		plainError(w, http.StatusBadRequest, fmt.Sprintf("unsupported scheme %q in a plain proxy request; HTTPS clients must use CONNECT", r.URL.Scheme))
	case p.isSelf(r.URL):
		plainError(w, http.StatusLoopDetected, "request targets the proxy itself; refusing to forward it to avoid a loop")
	case isUpgrade(r):
		plainError(w, http.StatusNotImplemented, "protocol upgrades (e.g. WebSocket) are not supported")
	default:
		p.forward(w, r, p.transport)
	}
}

// forward relays one request to the target server using tr and records the
// exchange. r.URL must be absolute (http:// or https://). This is the single
// code path for plain HTTP and decrypted HTTPS, and it hosts both intercept
// pause points; a paused request blocks only this request's own goroutine, so
// other requests are never held up.
func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, tr *http.Transport) {
	start := time.Now()
	ex := &model.Exchange{
		Timestamp:  start,
		Source:     model.SourceProxy,
		Method:     r.Method,
		URL:        r.URL.String(),
		Host:       r.URL.Host,
		Path:       r.URL.RequestURI(),
		Proto:      r.Proto,
		ReqHeaders: r.Header.Clone(),
	}
	reqCap := outbound.NewCapture(p.cfg.MaxBodyBytes)
	respCap := outbound.NewCapture(p.cfg.MaxBodyBytes)
	var notes []string
	defer func() {
		ex.ReqBody, ex.ReqBodySize = reqCap.Bytes(), reqCap.Total()
		ex.RespBody, ex.RespBodySize = respCap.Bytes(), respCap.Total()
		ex.Note = strings.Join(notes, "; ")
		ex.Duration = time.Since(start)
		p.save(ex)
	}()
	ctx := r.Context()

	// The request as the client sent it, with Host made explicit so it can be
	// shown and edited like any other header.
	req := &model.Request{Method: r.Method, URL: r.URL.String(), Header: r.Header.Clone()}
	req.Header.Set("Host", r.Host)

	var body io.Reader // client's request body, nil if there is none
	if r.ContentLength != 0 && r.Body != nil && r.Body != http.NoBody {
		body = r.Body
	}

	// --- Pause point 1: request fully received, nothing sent upstream yet.
	needIntercept := p.icpt != nil && p.icpt.RequestEnabled()
	needRulesBody := p.re != nil && p.re.NeedsRequestBody()
	buffered := false
	if needIntercept || needRulesBody {
		var buf []byte
		whole := true
		if body != nil {
			var err error
			if buf, whole, err = outbound.ReadUpTo(body, p.cfg.MaxBodyBytes); err != nil {
				ex.StatusCode, ex.Error = http.StatusBadRequest, "reading request body: "+err.Error()
				plainError(w, ex.StatusCode, ex.Error)
				return
			}
		}
		if whole {
			req.Body, buffered = buf, true
		} else {
			notes = append(notes, skipNote("request", "body larger than -max-body", needIntercept, needRulesBody))
			body = io.MultiReader(bytes.NewReader(buf), body)
		}
	}
	// Rules that don't need the body (header/method/host scope only) still
	// run even when nothing was buffered above; only body-touching rules
	// require needRulesBody to have forced buffering first.
	var ruleFired []string
	if p.re != nil {
		ruleFired = p.re.ApplyRequest(req, buffered)
		if len(ruleFired) > 0 {
			ex.RulesApplied = append(ex.RulesApplied, ruleFired...)
		}
	}
	origBase := r.URL.Scheme + "://" + r.URL.Host
	if buffered && needIntercept {
		oc := p.icpt.HoldRequest(ctx, req)
		if oc.Note != "" {
			notes = append(notes, oc.Note)
		}
		if ctx.Err() != nil {
			ex.Error = "client disconnected while the request was held"
			return
		}
		if oc.Verdict == model.VerdictDrop {
			ex.StatusCode, ex.Error = http.StatusForbidden, "request dropped by intercept"
			plainError(w, ex.StatusCode, "request dropped by ProxyScope intercept")
			return
		}
		if oc.Edited {
			ex.ReqEdited = true
		}
	}
	if buffered || len(ruleFired) > 0 {
		// The stored copy must describe what was actually sent, whether a
		// rule, intercept, both, or (for a held-but-unmodified item) neither
		// changed it.
		recordEditedRequest(ex, req, buffered)
	}

	// A different scheme or host than the client asked for needs a transport
	// with matching TLS settings (the caller's may be pinned to another
	// name). Only intercept edits can change the URL; rule actions cannot.
	if ex.ReqEdited {
		if u, err := url.Parse(req.URL); err == nil && u.Scheme+"://"+u.Host != origBase {
			tr = p.out.Transport()
			defer tr.CloseIdleConnections()
		}
	}

	var outBody io.Reader
	var outLen int64
	switch {
	case buffered:
		if len(req.Body) > 0 {
			reqCap.Write(req.Body)
			outBody, outLen = bytes.NewReader(req.Body), int64(len(req.Body))
		}
	case body != nil:
		outBody, outLen = io.TeeReader(body, reqCap), r.ContentLength // -1 = chunked
	}
	out, err := outbound.BuildRequest(ctx, req.Method, req.URL, req.Header, outBody, outLen)
	if err != nil {
		ex.StatusCode, ex.Error = http.StatusBadRequest, err.Error()
		plainError(w, ex.StatusCode, "invalid request: "+err.Error())
		return
	}

	resp, err := tr.RoundTrip(out)
	if err != nil {
		status, msg := outbound.Classify(err, out.URL.Host)
		ex.StatusCode, ex.Error = status, msg
		if errors.Is(err, context.Canceled) {
			// Client went away; nobody to answer.
			ex.StatusCode = 0
			p.log.Debug("client cancelled request", "url", ex.URL)
			return
		}
		p.log.Warn("upstream request failed", "method", req.Method, "url", ex.URL, "err", err)
		plainError(w, status, msg)
		return
	}
	defer resp.Body.Close()

	ex.StatusCode = resp.StatusCode
	ex.RespHeaders = resp.Header.Clone()
	deliver := &model.Response{StatusCode: resp.StatusCode, Header: resp.Header.Clone()}

	// --- Pause point 2: response fully received, nothing sent to the client yet.
	needInterceptResp := p.icpt != nil && p.icpt.ResponseEnabled()
	needRulesRespBody := p.re != nil && p.re.NeedsResponseBody()
	bufferedResp := false
	if needInterceptResp || needRulesRespBody {
		if reason := notHoldable(resp, p.cfg.MaxBodyBytes); reason != "" {
			notes = append(notes, skipNote("response", reason, needInterceptResp, needRulesRespBody))
		} else {
			buf, whole, err := outbound.ReadUpTo(resp.Body, p.cfg.MaxBodyBytes)
			switch {
			case err != nil:
				// Nothing has been sent to the client yet, so it can still get a clean error.
				ex.StatusCode, ex.Error, ex.RespHeaders = http.StatusBadGateway, "reading response body from upstream: "+err.Error(), nil
				if ctx.Err() != nil {
					ex.StatusCode = 0
					return
				}
				plainError(w, ex.StatusCode, ex.Error)
				return
			case whole:
				deliver.Body, bufferedResp = buf, true
			default:
				notes = append(notes, skipNote("response", "body larger than -max-body", needInterceptResp, needRulesRespBody))
				resp.Body = struct {
					io.Reader
					io.Closer
				}{io.MultiReader(bytes.NewReader(buf), resp.Body), resp.Body}
			}
		}
	}
	// Rules that don't need the body (status/header scope only) still run
	// even when nothing was buffered above, exactly like the request side.
	var respRuleFired []string
	if p.re != nil {
		respRuleFired = p.re.ApplyResponse(req, deliver, bufferedResp)
		if len(respRuleFired) > 0 {
			ex.RulesApplied = append(ex.RulesApplied, respRuleFired...)
		}
	}
	if bufferedResp && needInterceptResp {
		oc := p.icpt.HoldResponse(ctx, req, deliver)
		if oc.Note != "" {
			notes = append(notes, oc.Note)
		}
		if ctx.Err() != nil {
			ex.StatusCode, ex.RespHeaders, ex.Error = 0, nil, "client disconnected while the response was held"
			return
		}
		if oc.Verdict == model.VerdictDrop {
			ex.StatusCode, ex.RespHeaders, ex.Error = http.StatusForbidden, nil, "response dropped by intercept"
			plainError(w, ex.StatusCode, "response dropped by ProxyScope intercept")
			return
		}
		ex.RespEdited = oc.Edited
	}
	if bufferedResp || len(respRuleFired) > 0 {
		// The stored copy must describe what was actually delivered, whether
		// a rule, intercept, both, or neither changed it.
		ex.StatusCode, ex.RespHeaders = deliver.StatusCode, deliver.Header.Clone()
	}

	h := w.Header()
	for k, vv := range deliver.Header {
		h[k] = append([]string(nil), vv...)
	}
	outbound.RemoveHopByHop(h)
	if bufferedResp {
		// The body is fully buffered, so the length is known (and may have been edited).
		canHaveBody := bodyAllowed(req.Method, deliver.StatusCode)
		if canHaveBody {
			h.Set("Content-Length", strconv.Itoa(len(deliver.Body)))
		}
		w.WriteHeader(deliver.StatusCode)
		if canHaveBody {
			respCap.Write(deliver.Body)
			if _, err := w.Write(deliver.Body); err != nil {
				ex.Error = "relaying response body: " + err.Error()
			}
		}
		return
	}
	w.WriteHeader(deliver.StatusCode)

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

// skipNote explains why a request/response body could not be buffered for
// rules and/or intercept (too large, or a streaming response), naming
// whichever of the two features actually needed it, e.g. "response not
// intercepted/rule-processed: body larger than -max-body".
func skipNote(what, reason string, needIntercept, needRules bool) string {
	var skipped []string
	if needIntercept {
		skipped = append(skipped, "intercepted")
	}
	if needRules {
		skipped = append(skipped, "rule-processed")
	}
	return fmt.Sprintf("%s not %s: %s", what, strings.Join(skipped, "/"), reason)
}

// recordEditedRequest makes the stored exchange describe what was actually
// sent: req may be unchanged (a held-but-forwarded-as-is item), rule-edited,
// intercept-edited, or both. syncContentLength must be false when req.Body
// was never buffered (e.g. only a header-only rule fired): in that case
// req.Body is empty regardless of whether the real (still-streaming) body is,
// and correcting Content-Length from it would wrongly report "no body".
func recordEditedRequest(ex *model.Exchange, req *model.Request, syncContentLength bool) {
	ex.Method, ex.URL = req.Method, req.URL
	if u, err := url.Parse(req.URL); err == nil {
		ex.Host, ex.Path = u.Host, u.RequestURI()
	}
	ex.ReqHeaders = req.Header.Clone()
	ex.ReqHeaders.Del("Host") // like live traffic: the host is shown separately
	if syncContentLength {
		outbound.SyncContentLength(ex.ReqHeaders, len(req.Body))
	}
}

// notHoldable says why a response must stream through instead of being held
// for editing ("" = it can be held).
func notHoldable(resp *http.Response, max int64) string {
	if strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")), "text/event-stream") {
		return "streaming response (text/event-stream)"
	}
	if resp.ContentLength > max {
		return "body larger than -max-body"
	}
	return ""
}

// bodyAllowed reports whether a response to method with this status carries a body.
func bodyAllowed(method string, status int) bool {
	return method != http.MethodHead && status >= 200 && status != http.StatusNoContent && status != http.StatusNotModified
}

// copyBody streams resp.Body to w while recording it. The bool result tells
// whether a returned error came from the upstream side (true) or the client (false).
func copyBody(w http.ResponseWriter, resp *http.Response, rec *outbound.Capture) (upstream bool, err error) {
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
	return p.isSelfAddr(u.Hostname(), port)
}

func (p *Proxy) isSelfAddr(host, port string) bool {
	if port != p.selfPort {
		return false
	}
	if strings.EqualFold(host, "localhost") || host == p.selfHost {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsLoopback() || ip.IsUnspecified())
}

func plainError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	fmt.Fprintf(w, "proxyscope: %s\n", msg)
}
