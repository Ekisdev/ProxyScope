package ca

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func pool(a *Authority) *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(a.cert)
	return p
}

func TestCreateThenLoadSameCA(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "ca")
	a, created, err := LoadOrCreate(dir)
	if err != nil || !created {
		t.Fatalf("create: created=%v err=%v", created, err)
	}
	b, created, err := LoadOrCreate(dir)
	if err != nil || created {
		t.Fatalf("load: created=%v err=%v", created, err)
	}
	if a.Fingerprint() != b.Fingerprint() {
		t.Fatal("reloaded CA differs")
	}
	if strings.Contains(string(a.CertPEM()), "PRIVATE") {
		t.Fatal("CertPEM must not contain the key")
	}
}

func TestInconsistentDirIsRefused(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := LoadOrCreate(dir); err != nil {
		t.Fatal(err)
	}
	os.Remove(filepath.Join(dir, KeyFile))
	if _, _, err := LoadOrCreate(dir); err == nil || !strings.Contains(err.Error(), "inconsistent") {
		t.Fatalf("err = %v", err)
	}
}

func TestMismatchedKeyIsRefused(t *testing.T) {
	d1, d2 := t.TempDir(), t.TempDir()
	LoadOrCreate(d1)
	LoadOrCreate(d2)
	k, _ := os.ReadFile(filepath.Join(d2, KeyFile))
	os.WriteFile(filepath.Join(d1, KeyFile), k, 0o600)
	if _, _, err := LoadOrCreate(d1); err == nil || !strings.Contains(err.Error(), "do not belong together") {
		t.Fatalf("err = %v", err)
	}
}

func TestLeafVerifiesAndIsCached(t *testing.T) {
	a, _, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Example.COM", "sub.example.com.", "127.0.0.1", "::1", "my_host.local"} {
		c, err := a.CertificateFor(name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		host, _, _ := NormalizeName(name)
		if _, err := c.Leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: pool(a)}); err != nil {
			t.Errorf("%s does not verify: %v", name, err)
		}
		again, _ := a.CertificateFor(name)
		if again != c {
			t.Errorf("%s: cert was not cached", name)
		}
	}
}

func TestInvalidNamesRejected(t *testing.T) {
	a, _, _ := LoadOrCreate(t.TempDir())
	for _, n := range []string{"", " ", "*.example.com", "exa mple.com", "a..b", "ex\x00ample.com", "bücher.de", strings.Repeat("a", 64) + ".com", strings.Repeat("a.", 130)} {
		if _, err := a.CertificateFor(n); err == nil {
			t.Errorf("name %q should be rejected", n)
		}
	}
}
