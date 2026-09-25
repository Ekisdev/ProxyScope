// Package repeater re-sends an (edited) request directly to its target and
// stores the result in history marked as replayed.
//
// It reuses the outbound package (same dialing, timeouts, TLS validation flag
// and error classification as the proxy) but deliberately bypasses both the
// proxy listener and the intercept queue: a repeater send never re-enters the
// proxy and is never held.
package repeater

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"proxyscope/internal/model"
	"proxyscope/internal/outbound"
)

// overallTimeout bounds one send including reading the whole response body,
// so an endless stream cannot hang a repeater request forever. Connection and
// response-header waits are bounded separately by the outbound config.
const overallTimeout = 2 * time.Minute

// Sink stores finished exchanges (implemented by the storage layer).
type Sink interface {
	Save(ctx context.Context, ex *model.Exchange) error
}

// Config holds repeater settings.
type Config struct {
	MaxBodyBytes int64
	Outbound     outbound.Config
}

// Service sends repeater requests.
type Service struct {
	cfg       Config
	sink      Sink
	transport *http.Transport
}

// New creates a Service.
func New(cfg Config, sink Sink) *Service {
	return &Service{cfg: cfg, sink: sink, transport: cfg.Outbound.Transport()}
}

// Close releases idle upstream connections.
func (s *Service) Close() { s.transport.CloseIdleConnections() }

// Send performs req and returns the stored exchange (Source "repeater").
// Network-level failures (refused, timeout, invalid upstream certificate, ...)
// are not Go errors: they are recorded in Exchange.Error like for live traffic.
// A returned error means the request itself was unusable, or storing failed.
func (s *Service) Send(ctx context.Context, req *model.Request) (*model.Exchange, error) {
	u, err := url.Parse(req.URL)
	if err != nil {
		return nil, fmt.Errorf("%w: URL: %v", model.ErrInvalidRequest, err)
	}
	reqCap := outbound.NewCapture(s.cfg.MaxBodyBytes)
	var body io.Reader
	if len(req.Body) > 0 {
		reqCap.Write(req.Body)
		body = bytes.NewReader(req.Body)
	}
	ctx, cancel := context.WithTimeout(ctx, overallTimeout)
	defer cancel()
	out, err := outbound.BuildRequest(ctx, req.Method, req.URL, req.Header, body, int64(len(req.Body)))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", model.ErrInvalidRequest, err)
	}

	start := time.Now()
	ex := &model.Exchange{
		Timestamp:  start,
		Source:     model.SourceRepeater,
		Method:     req.Method,
		URL:        req.URL,
		Host:       u.Host,
		Path:       u.RequestURI(),
		Proto:      "HTTP/1.1",
		ReqHeaders: req.Header.Clone(),
	}
	ex.ReqHeaders.Del("Host") // like live traffic: the host is shown separately
	outbound.SyncContentLength(ex.ReqHeaders, len(req.Body))
	respCap := outbound.NewCapture(s.cfg.MaxBodyBytes)

	resp, err := s.transport.RoundTrip(out)
	if err != nil {
		_, ex.Error = outbound.Classify(err, out.URL.Host)
	} else {
		ex.StatusCode, ex.RespHeaders = resp.StatusCode, resp.Header.Clone()
		if _, err := io.Copy(respCap, resp.Body); err != nil {
			ex.Error = "reading response body: " + err.Error()
		}
		resp.Body.Close()
	}
	ex.ReqBody, ex.ReqBodySize = reqCap.Bytes(), reqCap.Total()
	ex.RespBody, ex.RespBodySize = respCap.Bytes(), respCap.Total()
	ex.Duration = time.Since(start)

	// Store even if the caller went away: the send did happen.
	saveCtx, saveCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer saveCancel()
	if err := s.sink.Save(saveCtx, ex); err != nil {
		return nil, fmt.Errorf("saving repeater result: %w", err)
	}
	return ex, nil
}
