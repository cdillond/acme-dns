package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"slices"
	"testing"
)

func TestNewCSRIncludesDNSNames(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	names := []string{"example.com", "*.example.com", "xn--bcher-kva.example"}
	out, err := newCSR(key, names)
	if err != nil {
		t.Fatal(err)
	}

	der, err := base64.RawURLEncoding.DecodeString(out.CSR)
	if err != nil {
		t.Fatal(err)
	}
	req, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	if err = req.CheckSignature(); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(req.DNSNames, names) {
		t.Fatalf("DNSNames = %q, want %q", req.DNSNames, names)
	}
	pub, ok := req.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("public key type = %T, want *ecdsa.PublicKey", req.PublicKey)
	}
	if !pub.Equal(&key.PublicKey) {
		t.Fatal("CSR public key does not match input key")
	}
}
