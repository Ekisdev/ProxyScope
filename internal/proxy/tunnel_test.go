package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"proxyscope/internal/ca"
)

func httpsClient(proxyURL *url.URL, roots *x509.CertPool) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{RootCAs: roots},
		},
		Timeout: 5 * time.Second,
	}
}

func caPool(a *ca.Authority) *x509.CertPool {
	p := x509.NewCertPool()
	p.AppendCertsFromPEM(a.CertPEM())
	return p
}

func newTLSUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Seen-Host", r.Host)
		io.WriteString(w, "secure:"+r.URL.RequestURI()+":"+string(b))
	}))
	t.Cleanup(up.Close)
	return up
}

func TestHTTPSInterceptionIsDecryptedAndRecorded(t *testing.T) {
	up := newTLSUpstream(t)
	upPool := x509.NewCertPool()
	upPool.AddCert(up.Certificate())
	pu, sink, authority := startProxy(t, Config{
		MaxBodyBytes: 1 << 20, DialTimeout: time.Second, HeaderTimeout: 2 * time.Second,
		UpstreamRootCAs: upPool, // trust the test upstream's self-signed cert
	})
	c := httpsClient(pu, caPool(authority)) // client trusts only the ProxyScope CA

	resp, err := c.Post(up.URL+"/p?q=1", "text/plain", strings.NewReader("hello"))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "secure:/p?q=1:hello" {
		t.Fatalf("got %d %q", resp.StatusCode, body)
	}
	// The certificate the client saw was issued by our CA for the target.
	if resp.TLS == nil || resp.TLS.PeerCertificates[0].Issuer.CommonName != "ProxyScope Local CA" {
		t.Fatalf("client did not see a ProxyScope leaf: %+v", resp.TLS)
	}

	ex := sink.last(t)
	wantHost := strings.TrimPrefix(up.URL, "https://") // 127.0.0.1:<port>
	if ex.URL != up.URL+"/p?q=1" || ex.Host != wantHost || ex.Method != "POST" || ex.StatusCode != 200 ||
		string(ex.ReqBody) != "hello" || string(ex.RespBody) != "secure:/p?q=1:hello" || ex.Error != "" {
		t.Fatalf("bad exchange: %+v", ex)
	}
}

func TestKeepAliveTunnelServesMultipleRequests(t *testing.T) {
	up := newTLSUpstream(t)
	pu, sink, authority := startProxy(t, Config{MaxBodyBytes: 1 << 20, DialTimeout: time.Second, HeaderTimeout: 2 * time.Second, InsecureUpstream: true})
	c := httpsClient(pu, caPool(authority))
	for _, path := range []string{"/a", "/b", "/c"} {
		resp, err := c.Get(up.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.got) != 3 {
		t.Fatalf("recorded %d exchanges, want 3", len(sink.got))
	}
}

func TestUpstreamCertValidationOnByDefault(t *testing.T) {
	up := newTLSUpstream(t) // self-signed, not in system roots
	pu, sink, authority := startProxy(t, Config{MaxBodyBytes: 1 << 20, DialTimeout: time.Second, HeaderTimeout: 2 * time.Second})
	c := httpsClient(pu, caPool(authority))

	resp, err := c.Get(up.URL + "/")
	if err != nil {
		t.Fatalf("client must get a readable response through the tunnel, got error: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway || !strings.Contains(string(body), "failed validation") ||
		!strings.Contains(string(body), "-insecure-upstream") {
		t.Fatalf("got %d %q", resp.StatusCode, body)
	}
	if ex := sink.last(t); ex.StatusCode != 502 || !strings.Contains(ex.Error, "failed validation") {
		t.Fatalf("bad exchange: %+v", ex)
	}
}

func TestInsecureUpstreamAcceptsInvalidCert(t *testing.T) {
	up := newTLSUpstream(t)
	pu, _, authority := startProxy(t, Config{MaxBodyBytes: 1 << 20, DialTimeout: time.Second, HeaderTimeout: 2 * time.Second, InsecureUpstream: true})
	resp, err := httpsClient(pu, caPool(authority)).Get(up.URL + "/x")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestClientRejectingFakeCertFailsCleanlyAndIsRecorded(t *testing.T) {
	up := newTLSUpstream(t)
	pu, sink, _ := startProxy(t, Config{MaxBodyBytes: 1 << 20, DialTimeout: time.Second, HeaderTimeout: 2 * time.Second, InsecureUpstream: true})
	c := httpsClient(pu, nil) // client does NOT trust the ProxyScope CA

	if _, err := c.Get(up.URL + "/"); err == nil {
		t.Fatal("client should have rejected the ProxyScope certificate")
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		sink.mu.Lock()
		n := len(sink.got)
		sink.mu.Unlock()
		if n > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	ex := sink.last(t)
	if ex.Method != "CONNECT" || ex.StatusCode != 0 || !strings.Contains(ex.Error, "trust") {
		t.Fatalf("handshake failure not recorded usefully: %+v", ex)
	}
}

func TestClientClosingMidHandshakeIsRecorded(t *testing.T) {
	// Open a tunnel, then vanish before sending a ClientHello.
	pu, sink, _ := startProxy(t, Config{MaxBodyBytes: 1 << 10, DialTimeout: time.Second, HeaderTimeout: time.Second})
	conn, err := net.Dial("tcp", pu.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	io.WriteString(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, _ := conn.Read(buf)
	if !strings.HasPrefix(string(buf[:n]), "HTTP/1.1 200") {
		t.Fatalf("tunnel not established: %q", buf[:n])
	}
	// We can't wait the full 15s in a unit test; closing the connection
	// mid-handshake must be recorded rather than leak the goroutine.
	conn.Close()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		sink.mu.Lock()
		n := len(sink.got)
		sink.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if ex := sink.last(t); ex.Method != "CONNECT" || ex.Error == "" {
		t.Fatalf("bad exchange: %+v", ex)
	}
}

func TestInvalidSNIIsRejected(t *testing.T) {
	pu, sink, authority := startProxy(t, Config{MaxBodyBytes: 1 << 10, DialTimeout: time.Second, HeaderTimeout: time.Second})
	conn, err := net.Dial("tcp", pu.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	io.WriteString(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	buf := make([]byte, 64)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	conn.Read(buf)

	tc := tls.Client(conn, &tls.Config{ServerName: "bad name!.example", RootCAs: caPool(authority)})
	if err := tc.Handshake(); err == nil {
		t.Fatal("handshake with an invalid SNI should fail")
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		sink.mu.Lock()
		n := len(sink.got)
		sink.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if ex := sink.last(t); ex.Method != "CONNECT" || ex.StatusCode != 0 || ex.Error == "" {
		t.Fatalf("bad exchange: %+v", ex)
	}
}

func TestParseConnectTarget(t *testing.T) {
	for _, tc := range []struct {
		in, host, port string
		bad            bool
	}{
		{"example.com:443", "example.com", "443", false},
		{"example.com", "example.com", "443", false},
		{"[::1]:8443", "::1", "8443", false},
		{"1.2.3.4:80", "1.2.3.4", "80", false},
		{"example.com:0", "", "", true},
		{"example.com:99999", "", "", true},
		{"a b:443", "", "", true},
		{":443", "", "", true},
		{"a:b:c", "", "", true},
	} {
		h, p, err := parseConnectTarget(tc.in)
		if (err != nil) != tc.bad || (!tc.bad && (h != tc.host || p != tc.port)) {
			t.Errorf("%q => %q %q err=%v", tc.in, h, p, err)
		}
	}
	if got := hostPort("example.com", "443"); got != "example.com" {
		t.Errorf("hostPort default = %q", got)
	}
	if got := hostPort("::1", "8443"); got != "[::1]:8443" {
		t.Errorf("hostPort ipv6 = %q", got)
	}
}
