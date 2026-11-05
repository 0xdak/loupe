// Package ca manages the local certificate authority used to intercept TLS.
//
// The authority signs a certificate for every host on demand. All host
// certificates share one key pair, so a browser started by lightproxy can be
// told to trust exactly that key (Chromium's --ignore-certificate-errors-spki-list)
// without the CA being installed anywhere.
package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
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

const (
	certFile    = "ca-cert.pem"
	keyFile     = "ca-key.pem"
	leafKeyFile = "leaf-key.pem"

	caValidity = 10 * 365 * 24 * time.Hour
	// Apple rejects server certificates valid for more than 825 days, even
	// under a user-installed root; one year stays well inside every limit.
	leafValidity = 365 * 24 * time.Hour
	maxCached    = 2000
)

// Authority signs host certificates. It is safe for concurrent use.
type Authority struct {
	cert    *x509.Certificate
	certPEM []byte
	key     crypto.Signer
	leafKey *ecdsa.PrivateKey
	dir     string

	mu    sync.Mutex
	cache map[string]*tls.Certificate
}

// LoadOrCreate loads the authority stored in dir, creating one on first use.
func LoadOrCreate(dir string) (*Authority, error) {
	a, err := load(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return create(dir)
	}
	return a, err
}

// Dir is the directory holding the authority's files.
func (a *Authority) Dir() string { return a.dir }

// CertPEM is the CA certificate in PEM form, for installing in trust stores.
func (a *Authority) CertPEM() []byte { return a.certPEM }

// LeafSPKIHash is the base64 SHA-256 of the public key shared by all host
// certificates, in the form Chromium's --ignore-certificate-errors-spki-list expects.
func (a *Authority) LeafSPKIHash() string {
	der, _ := x509.MarshalPKIXPublicKey(&a.leafKey.PublicKey)
	sum := sha256.Sum256(der)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// ServerConfig returns a TLS configuration that presents a certificate for
// the SNI name the client asks for, or for fallbackHost when it sends none.
func (a *Authority) ServerConfig(fallbackHost string) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			host := hello.ServerName
			if host == "" {
				host = fallbackHost
			}
			return a.CertFor(host)
		},
	}
}

// CertFor returns a certificate for host signed by the authority.
func (a *Authority) CertFor(host string) (*tls.Certificate, error) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return nil, errors.New("ca: empty host name")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if c, ok := a.cache[host]; ok && time.Until(c.Leaf.NotAfter) > 24*time.Hour {
		return c, nil
	}
	c, err := a.sign(host)
	if err != nil {
		return nil, err
	}
	if len(a.cache) >= maxCached {
		clear(a.cache)
	}
	a.cache[host] = c
	return c, nil
}

func (a *Authority) sign(host string) (*tls.Certificate, error) {
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: host, Organization: []string{"lightproxy"}},
		NotBefore:             now.Add(-24 * time.Hour), // tolerate clock skew
		NotAfter:              now.Add(leafValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, &a.leafKey.PublicKey, a.key)
	if err != nil {
		return nil, fmt.Errorf("ca: signing certificate for %s: %w", host, err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der, a.cert.Raw}, PrivateKey: a.leafKey, Leaf: leaf}, nil
}

func create(dir string) (*Authority, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	hostname, _ := os.Hostname()
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		// A per-installation name makes the CA easy to find and remove in a trust store.
		Subject: pkix.Name{
			CommonName:   fmt.Sprintf("lightproxy CA (%s, %s)", hostname, now.Format("2006-01-02")),
			Organization: []string{"lightproxy"},
		},
		NotBefore:             now.Add(-24 * time.Hour),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := writeKey(filepath.Join(dir, keyFile), caKey); err != nil {
		return nil, err
	}
	if err := writeKey(filepath.Join(dir, leafKeyFile), leafKey); err != nil {
		return nil, err
	}
	// The certificate is written last: its presence marks a complete authority.
	if err := os.WriteFile(filepath.Join(dir, certFile), certPEM, 0o644); err != nil {
		return nil, err
	}
	return load(dir)
}

func load(dir string) (*Authority, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, certFile))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("ca: %s is not a PEM certificate", certFile)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	caKey, err := readKey(filepath.Join(dir, keyFile))
	if err != nil {
		return nil, err
	}
	leafKey, err := readKey(filepath.Join(dir, leafKeyFile))
	if err != nil {
		return nil, err
	}
	return &Authority{
		cert: cert, certPEM: certPEM, key: caKey, leafKey: leafKey, dir: dir,
		cache: map[string]*tls.Certificate{},
	}, nil
}

func writeKey(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	return os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600)
}

func readKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("ca: %s is not PEM", filepath.Base(path))
	}
	return x509.ParseECPrivateKey(block.Bytes)
}

func randomSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}
