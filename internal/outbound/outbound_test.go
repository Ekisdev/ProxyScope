package outbound

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestBuildRequestHostHopByHopAndUA(t *testing.T) {
	h := http.Header{
		"Host":       {"virtual.example"},
		"Connection": {"keep-alive, X-Secret"},
		"X-Secret":   {"1"},
		"X-Keep":     {"yes"},
	}
	req, err := BuildRequest(context.Background(), "POST", "http://127.0.0.1:1/p", h, strings.NewReader("abc"), 3)
	if err != nil {
		t.Fatal(err)
	}
	if req.Host != "virtual.example" || req.Header.Get("Host") != "" {
		t.Fatalf("host handling: %q %v", req.Host, req.Header)
	}
	if req.Header.Get("Connection") != "" || req.Header.Get("X-Secret") != "" || req.Header.Get("X-Keep") != "yes" {
		t.Fatalf("hop-by-hop handling: %v", req.Header)
	}
	if v, ok := req.Header["User-Agent"]; !ok || v[0] != "" {
		t.Fatalf("default User-Agent must be suppressed: %v", req.Header)
	}
	if req.ContentLength != 3 {
		t.Fatalf("content length = %d", req.ContentLength)
	}
}

func TestBuildRequestRejectsBadTargets(t *testing.T) {
	for _, u := range []string{"ftp://x/", "http:///path", "/relative", "://bad"} {
		if _, err := BuildRequest(context.Background(), "GET", u, nil, nil, 0); err == nil {
			t.Errorf("%q should be rejected", u)
		}
	}
}

func TestCaptureAndReadUpTo(t *testing.T) {
	c := NewCapture(4)
	c.Write([]byte("ab"))
	c.Write([]byte("cdef"))
	if string(c.Bytes()) != "abcd" || c.Total() != 6 {
		t.Fatalf("capture = %q/%d", c.Bytes(), c.Total())
	}
	buf, whole, _ := ReadUpTo(bytes.NewReader([]byte("12345")), 5)
	if !whole || string(buf) != "12345" {
		t.Fatalf("exact fit: %q %v", buf, whole)
	}
	buf, whole, _ = ReadUpTo(bytes.NewReader([]byte("123456")), 5)
	if whole || string(buf) != "123456" {
		t.Fatalf("overflow: %q %v", buf, whole)
	}
}
