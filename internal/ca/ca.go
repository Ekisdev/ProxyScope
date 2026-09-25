// Package ca manages the local root certificate authority used for TLS
// interception and issues per-host leaf certificates signed by it.
//
// All certificate/key handling lives in this package. The private key never
// leaves it: the only exported material is the public certificate.
package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// File names inside the CA directory.
const (
	CertFile = "ca.crt" // public certificate, safe to share/install
	KeyFile  = "ca.key" // private key, must stay secret
)

const (
	caValidity      = 10 * 365 * 24 * time.Hour
	leafValidity    = 365 * 24 * time.Hour
	leafRenewMargin = 24 * time.Hour // regenerate cached leaves this close to expiry
	clockSkew       = time.Hour
	maxCacheSize    = 2048
)

// Authority is a loaded root CA that can issue leaf certificates. It is safe
// for concurrent use.
type Authority struct {
	dir     string
	cert    *x509.Certificate
	certPEM []byte
	key     *ecdsa.PrivateKey

	mu    sync.Mutex
	cache map[string]*tls.Certificate
}

// LoadOrCreate loads the CA from dir, generating a new one (key + self-signed
// certificate) if neither file exists. It refuses to continue when only one of
// the two files is present, rather than silently replacing a CA the user may
// already have installed in a trust store.
func LoadOrCreate(dir string) (a *Authority, created bool, err error) {
	keyPath, certPath := filepath.Join(dir, KeyFile), filepath.Join(dir, CertFile)
	keyExists, err := exists(keyPath)
	if err != nil {
		return nil, false, err
	}
	certExists, err := exists(certPath)
	if err != nil {
		return nil, false, err
	}
	switch {
	case keyExists && certExists:
		a, err = load(dir)
		return a, false, err
	case !keyExists && !certExists:
		a, err = create(dir)
		return a, true, err
	default:
		return nil, false, fmt.Errorf("CA directory %s is inconsistent: exactly one of %s and %s exists; restore the missing file or delete the other to generate a new CA", dir, CertFile, KeyFile)
	}
}

func exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return false, fmt.Errorf("check %s: %w", path, err)
}

func create(dir string) (*Authority, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create CA directory: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "ProxyScope Local CA", Organization: []string{"ProxyScope"}},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create CA certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("encode CA key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyPath, certPath := filepath.Join(dir, KeyFile), filepath.Join(dir, CertFile)
	// O_EXCL: never overwrite an existing key. Mode 0600 is enforced on Linux;
	// on Windows the file inherits the private ACL of the user profile.
	if err := writeNew(keyPath, keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("write CA key: %w", err)
	}
	if err := writeNew(certPath, certPEM, 0o644); err != nil {
		os.Remove(keyPath) // don't leave a half-created CA behind
		return nil, fmt.Errorf("write CA certificate: %w", err)
	}
	return load(dir)
}

func writeNew(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func load(dir string) (*Authority, error) {
	keyPEM, err := os.ReadFile(filepath.Join(dir, KeyFile))
	if err != nil {
		return nil, fmt.Errorf("read CA key: %w", err)
	}
	certPEM, err := os.ReadFile(filepath.Join(dir, CertFile))
	if err != nil {
		return nil, fmt.Errorf("read CA certificate: %w", err)
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, fmt.Errorf("%s does not contain a PEM block", KeyFile)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", KeyFile, err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s is not an ECDSA key", KeyFile)
	}
	cb, _ := pem.Decode(certPEM)
	if cb == nil {
		return nil, fmt.Errorf("%s does not contain a PEM block", CertFile)
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", CertFile, err)
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("%s is not a CA certificate", CertFile)
	}
	if !key.PublicKey.Equal(cert.PublicKey) {
		return nil, fmt.Errorf("%s and %s do not belong together", CertFile, KeyFile)
	}
	if time.Now().After(cert.NotAfter) {
		return nil, fmt.Errorf("the CA certificate expired on %s; delete %s and %s in %s to generate a new one (it must be installed again)",
			cert.NotAfter.Format(time.DateOnly), CertFile, KeyFile, dir)
	}
	return &Authority{dir: dir, cert: cert, certPEM: certPEM, key: key, cache: map[string]*tls.Certificate{}}, nil
}

// Dir returns the directory holding the CA files.
func (a *Authority) Dir() string { return a.dir }

// CertPath returns the path of the public CA certificate file.
func (a *Authority) CertPath() string { return filepath.Join(a.dir, CertFile) }

// CertPEM returns the public CA certificate in PEM form.
func (a *Authority) CertPEM() []byte { return append([]byte(nil), a.certPEM...) }

// Fingerprint returns the SHA-256 fingerprint of the CA certificate, for
// comparing against what the OS/browser shows after installation.
func (a *Authority) Fingerprint() string {
	sum := sha256.Sum256(a.cert.Raw)
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

// CertificateFor returns a leaf certificate for name (a DNS name or IP
// address) signed by the CA. Results are cached per name.
func (a *Authority) CertificateFor(name string) (*tls.Certificate, error) {
	host, ip, err := NormalizeName(name)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if c, ok := a.cache[host]; ok && time.Until(c.Leaf.NotAfter) > leafRenewMargin {
		return c, nil
	}
	c, err := a.issue(host, ip)
	if err != nil {
		return nil, err
	}
	if len(a.cache) >= maxCacheSize {
		clear(a.cache) // crude but bounded; regenerating a P-256 leaf is cheap
	}
	a.cache[host] = c
	return c, nil
}

func (a *Authority) issue(host string, ip net.IP) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: truncate(host, 64)},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.Add(leafValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, &key.PublicKey, a.key)
	if err != nil {
		return nil, fmt.Errorf("sign leaf certificate for %s: %w", host, err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse leaf certificate for %s: %w", host, err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

// NormalizeName validates and canonicalizes a TLS server name. It accepts IP
// literals and plain ASCII DNS names (IDNs must already be in punycode, which
// is what clients put in SNI). It rejects empty names, wildcards, whitespace,
// and anything else that is not a plausible host name.
func NormalizeName(name string) (host string, ip net.IP, err error) {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if name == "" {
		return "", nil, errors.New("empty server name")
	}
	if ip := net.ParseIP(name); ip != nil {
		return ip.String(), ip, nil
	}
	if len(name) > 253 {
		return "", nil, errors.New("server name too long")
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return "", nil, fmt.Errorf("invalid server name %q", truncate(name, 80))
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return "", nil, fmt.Errorf("invalid server name %q", truncate(name, 80))
			}
		}
	}
	return name, nil, nil
}

func newSerial() (*big.Int, error) {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, fmt.Errorf("generate serial number: %w", err)
	}
	return n.Add(n, big.NewInt(1)), nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// ExportCert writes the public CA certificate (never the key) to path as PEM.
func (a *Authority) ExportCert(path string) error {
	if err := os.WriteFile(path, a.certPEM, 0o644); err != nil {
		return fmt.Errorf("export CA certificate: %w", err)
	}
	return nil
}
