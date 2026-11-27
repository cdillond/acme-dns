package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"
)

func TestNewAccountKey(t *testing.T) {
	key, err := NewAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	pk, ok := key.PrivateKey().(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("private key type = %T, want *ecdsa.PrivateKey", key.PrivateKey())
	}
	if pk.Curve != elliptic.P256() {
		t.Fatalf("curve = %v, want P-256", pk.Curve.Params().Name)
	}
}

func TestNewAccountKeyFromECDSAP256(t *testing.T) {
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	key, err := NewAccountKeyFromECDSAP256(pk)
	if err != nil {
		t.Fatal(err)
	}
	if key.PrivateKey() != pk {
		t.Error("NewAccountKeyFromECDSAP256 did not wrap the supplied private key")
	}

	j, err := key.newJWK()
	if err != nil {
		t.Fatal(err)
	}
	wantThumbprint, err := j.appendThumbprint(nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(key.thumbprint) != string(wantThumbprint) {
		t.Errorf("thumbprint = %x, want %x", key.thumbprint, wantThumbprint)
	}
}

func TestNewAccountKeyFromECDSAP256RejectsOtherCurves(t *testing.T) {
	pk, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewAccountKeyFromECDSAP256(pk)
	if err == nil {
		t.Fatal("NewAccountKeyFromECDSAP256 accepted a P-384 key")
	}
	if !strings.Contains(err.Error(), "unsupported account key type") {
		t.Fatalf("error = %q, want unsupported key type error", err)
	}
}
