package ca

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"testing"
)

func TestCreateReloadAndSign(t *testing.T) {
	dir := t.TempDir()
	a, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if string(a.CertPEM()) != string(b.CertPEM()) || a.LeafSPKIHash() != b.LeafSPKIHash() {
		t.Fatal("reloading created a different authority")
	}

	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(a.CertPEM())
	for _, host := range []string{"example.com", "127.0.0.1", "::1"} {
		c, err := b.CertFor(host)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: roots}); err != nil {
			t.Errorf("%s: certificate does not verify: %v", host, err)
		}
		der, _ := x509.MarshalPKIXPublicKey(c.Leaf.PublicKey)
		sum := sha256.Sum256(der)
		if base64.StdEncoding.EncodeToString(sum[:]) != b.LeafSPKIHash() {
			t.Errorf("%s: leaf key does not match LeafSPKIHash", host)
		}
	}

	c1, _ := b.CertFor("Example.COM.")
	c2, _ := b.CertFor("example.com")
	if c1 != c2 {
		t.Error("host names differing only in case and trailing dot were not cached together")
	}
}
