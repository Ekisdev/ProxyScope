package proxy

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"proxyscope/internal/model"
)

const (
	handshakeTimeout  = 15 * time.Second // client TLS handshake must not hang
	tunnelIdleTimeout = 2 * time.Minute
)

// handleConnect answers a CONNECT request by hijacking the connection,
// terminating TLS towards the client with a certificate issued for the
// requested host, and serving the decrypted HTTP/1.1 stream through the
// regular forwarding path. Each decrypted request is recorded as an ordinary
// exchange with an https:// URL.
//
// Names used (kept consistent on purpose):
//   - leaf certificate name: the client's SNI if present, else the CONNECT host
//   - upstream address:      always the CONNECT host:port
//   - upstream TLS name:     the leaf certificate name (what the client asked for)
func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	host, port, err := parseConnectTarget(r.Host)
	if err != nil {
		plainError(w, http.StatusBadRequest, "invalid CONNECT target: "+err.Error())
		return
	}
	if p.isSelfAddr(host, port) {
		plainError(w, http.StatusLoopDetected, "CONNECT targets the proxy itself; refusing to avoid a loop")
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		plainError(w, http.StatusInternalServerError, "connection cannot be hijacked")
		return
	}
	conn, brw, err := hj.Hijack()
	if err != nil {
		p.log.Error("hijack failed", "target", r.Host, "err", err)
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Time{}) // the server may have left deadlines set

	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		p.log.Debug("client went away before tunnel was established", "target", r.Host, "err", err)
		return
	}
	var c net.Conn = conn
	if brw.Reader.Buffered() > 0 { // client already sent its ClientHello
		c = &bufferedConn{Conn: conn, r: brw.Reader}
	}
	p.serveTunnel(c, r, host, port)
}

// serveTunnel runs TLS towards the client on conn and relays its requests.
func (p *Proxy) serveTunnel(conn net.Conn, creq *http.Request, host, port string) {
	authority := hostPort(host, port)
	log := p.log.With("tunnel", authority)

	var leafName string
	tlsConn := tls.Server(conn, &tls.Config{
		// Only HTTP/1.1: the relay does not speak HTTP/2 (documented limitation).
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			leafName = hello.ServerName
			switch {
			case leafName == "":
				leafName = host // client sent no SNI (or connects by IP)
			case !strings.EqualFold(leafName, host):
				level := slog.LevelWarn
				if net.ParseIP(host) != nil {
					level = slog.LevelDebug // CONNECT by IP + SNI is normal
				}
				log.Log(creq.Context(), level, "SNI differs from CONNECT target; issuing certificate for the SNI", "sni", leafName)
			}
			return p.issuer.CertificateFor(leafName)
		},
	})
	_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
	if err := tlsConn.Handshake(); err != nil {
		p.clientHandshakeFailed(log, creq, authority, err)
		return
	}
	_ = conn.SetDeadline(time.Time{})

	serverName := leafName
	if net.ParseIP(leafName) != nil {
		serverName = "" // for IPs, net/http verifies against the dialed address
	}
	tr := p.out.NewTransport(p.out.TLSConfig(serverName))
	defer tr.CloseIdleConnections()

	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isUpgrade(r) {
				plainError(w, http.StatusNotImplemented, "protocol upgrades (e.g. WebSocket) are not supported")
				return
			}
			// Requests inside the tunnel are origin-form; make them absolute.
			r.URL.Scheme, r.URL.Host = "https", authority
			p.forward(w, r, tr)
		}),
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       tunnelIdleTimeout,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelDebug),
	}
	p.trackTunnel(srv, true)
	defer p.trackTunnel(srv, false)

	log.Debug("tunnel established", "sni", leafName)
	_ = srv.Serve(newOneConnListener(tlsConn)) // returns when the connection closes
	log.Debug("tunnel closed")
}

// clientHandshakeFailed logs and records a failed TLS handshake with the
// client. The most common cause is the client not trusting the ProxyScope CA.
func (p *Proxy) clientHandshakeFailed(log *slog.Logger, creq *http.Request, authority string, err error) {
	var opErr *net.OpError
	var msg string
	switch {
	case errors.As(err, &opErr) && opErr.Op == "remote error":
		msg = fmt.Sprintf("the client rejected the certificate presented by ProxyScope (%v): install the ProxyScope CA in the client's trust store (see README), or the client uses certificate pinning", err)
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		msg = "the client closed the connection during the TLS handshake: it probably does not trust the ProxyScope CA (or uses certificate pinning)"
	case isTimeout(err):
		msg = fmt.Sprintf("TLS handshake with the client timed out after %s", handshakeTimeout)
	default:
		msg = "TLS handshake with the client failed: " + err.Error()
	}
	log.Warn("client TLS handshake failed", "err", msg)
	p.save(&model.Exchange{
		Timestamp:  time.Now(),
		Method:     http.MethodConnect,
		URL:        "https://" + authority,
		Host:       authority,
		Proto:      creq.Proto,
		ReqHeaders: creq.Header.Clone(),
		Error:      msg,
	})
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func (p *Proxy) trackTunnel(srv *http.Server, add bool) {
	p.tunnelMu.Lock()
	defer p.tunnelMu.Unlock()
	if add {
		p.tunnels[srv] = struct{}{}
	} else {
		delete(p.tunnels, srv)
	}
}

// parseConnectTarget splits a CONNECT authority into host and port (default 443).
func parseConnectTarget(authority string) (host, port string, err error) {
	host, port = authority, "443"
	if h, pt, splitErr := net.SplitHostPort(authority); splitErr == nil {
		host, port = h, pt
	} else if strings.Contains(authority, ":") && !strings.HasPrefix(authority, "[") {
		return "", "", fmt.Errorf("malformed authority %q", truncate(authority))
	}
	host = strings.Trim(host, "[]")
	if host == "" || strings.ContainsAny(host, " \t\r\n\x00/@") {
		return "", "", fmt.Errorf("malformed host %q", truncate(authority))
	}
	if n, convErr := strconv.Atoi(port); convErr != nil || n < 1 || n > 65535 {
		return "", "", fmt.Errorf("invalid port %q", truncate(port))
	}
	return host, port, nil
}

// hostPort renders host:port for URLs, omitting the default HTTPS port.
func hostPort(host, port string) string {
	if port == "443" {
		if strings.Contains(host, ":") { // IPv6 literal
			return "[" + host + "]"
		}
		return host
	}
	return net.JoinHostPort(host, port)
}

func truncate(s string) string {
	if len(s) > 80 {
		return s[:80] + "…"
	}
	return s
}

// bufferedConn reads through a bufio.Reader that may already hold bytes the
// HTTP server read ahead before the connection was hijacked.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// oneConnListener is a net.Listener that yields a single connection and then
// blocks until that connection is closed, so http.Server.Serve can be used to
// serve exactly one (already established) connection.
type oneConnListener struct {
	ch   chan net.Conn
	done chan struct{}
	once sync.Once
}

func newOneConnListener(c net.Conn) *oneConnListener {
	l := &oneConnListener{ch: make(chan net.Conn, 1), done: make(chan struct{})}
	l.ch <- &notifyConn{Conn: c, l: l}
	return l
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *oneConnListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *oneConnListener) Addr() net.Addr { return dummyAddr{} }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "tunnel" }
func (dummyAddr) String() string  { return "tunnel" }

// notifyConn closes its listener when the connection is closed, which ends Serve.
type notifyConn struct {
	net.Conn
	l *oneConnListener
}

func (c *notifyConn) Close() error {
	err := c.Conn.Close()
	c.l.Close()
	return err
}
