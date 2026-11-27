package acme

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"go.ciaran.lol/acme-dns/acme/internal/fixtures"
)

func newTestLeafCert(t *testing.T) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"example.com"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func newTestCertKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestCertificateLeaf(t *testing.T) {
	cert := newTestLeafCert(t)
	if got := (Certificate{Chain: []*x509.Certificate{cert}}).Leaf(); got != cert {
		t.Error("Leaf did not return the first certificate")
	}
	if got := (Certificate{}).Leaf(); got != nil {
		t.Error("Leaf on an empty chain should be nil")
	}
	if got := (Certificate{Chain: []*x509.Certificate{nil}}).Leaf(); got != nil {
		t.Error("Leaf should be nil when the first certificate is nil")
	}
}

func TestCertificatePrivateKeyDER(t *testing.T) {
	key := newTestCertKey(t)
	der, err := (Certificate{PrivateKey: key}).PrivateKeyDER()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		t.Fatal(err)
	}
	pk, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || !pk.Equal(key) {
		t.Errorf("private key round trip = %T, want the original P-256 key", parsed)
	}

	if _, err = (Certificate{}).PrivateKeyDER(); err == nil {
		t.Error("PrivateKeyDER accepted an invalid private key")
	}
}

func TestCertificatePrivateKeyPEM(t *testing.T) {
	c := Certificate{PrivateKey: newTestCertKey(t)}
	der, err := c.PrivateKeyDER()
	if err != nil {
		t.Fatal(err)
	}

	pemBytes, err := c.PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PRIVATE KEY" || !bytes.Equal(block.Bytes, der) {
		t.Error("PrivateKeyPEM did not round trip the PKCS#8 key")
	}

	if _, err = (Certificate{}).PrivateKeyPEM(); err == nil {
		t.Error("PrivateKeyPEM accepted an invalid private key")
	}
}

func TestCertificateChainPEM(t *testing.T) {
	cert := newTestLeafCert(t)
	c := Certificate{Chain: []*x509.Certificate{cert}}
	if chain := c.ChainPEM(); !bytes.Equal(DecodePEM(chain), cert.Raw) {
		t.Error("ChainPEM/DecodePEM did not round trip the certificate")
	}
	if got := (Certificate{Chain: []*x509.Certificate{nil}}).ChainPEM(); got != nil {
		t.Error("ChainPEM should be nil when a certificate is nil")
	}
}

func TestCertificateChainDER(t *testing.T) {
	cert := newTestLeafCert(t)
	c := Certificate{Chain: []*x509.Certificate{cert}}
	if !bytes.Equal(c.ChainDER(), cert.Raw) {
		t.Error("ChainDER did not return the certificate DER")
	}
	if got := (Certificate{Chain: []*x509.Certificate{nil}}).ChainDER(); got != nil {
		t.Error("ChainDER should be nil when a certificate is nil")
	}
}

func TestShouldRenew(t *testing.T) {
	now := time.Now()
	withDates := func(notBefore, notAfter time.Time) []*x509.Certificate {
		cert := *newTestLeafCert(t)
		cert.NotBefore, cert.NotAfter = notBefore, notAfter
		return []*x509.Certificate{&cert}
	}

	cases := []struct {
		name  string
		chain []*x509.Certificate
		min   time.Duration
		want  bool
	}{
		{"empty chain", nil, time.Hour, true},
		{"nil leaf", []*x509.Certificate{nil}, time.Hour, true},
		{"not yet valid", withDates(now.Add(time.Hour), now.Add(48*time.Hour)), time.Hour, false},
		{"expiring soon", withDates(now.Add(-time.Hour), now.Add(30*time.Minute)), time.Hour, true},
		{"valid for a while", withDates(now.Add(-time.Hour), now.Add(2*time.Hour)), time.Hour, false},
		{"already expired", withDates(now.Add(-2*time.Hour), now.Add(-time.Hour)), time.Hour, true},
	}

	for _, tc := range cases {
		if got := ShouldRenew(tc.chain, tc.min); got != tc.want {
			t.Errorf("%s: ShouldRenew = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestParsePEMChain(t *testing.T) {
	cert := newTestLeafCert(t)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	input := append(append([]byte{}, pemBytes...), pemBytes...)
	input = append(input, []byte("trailing garbage")...)

	chain := parsePEMChain(input)
	if len(chain) != 2 {
		t.Fatalf("parsed %d certificates, want 2", len(chain))
	}
	for i, der := range chain {
		if !bytes.Equal(der, cert.Raw) {
			t.Errorf("chain[%d] does not match the input certificate", i)
		}
	}
	if chain := parsePEMChain([]byte("not pem")); len(chain) != 0 {
		t.Errorf("parsed %d certificates from invalid PEM, want 0", len(chain))
	}
}

func TestRevokeCert(t *testing.T) {
	key, err := NewAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	cert := newTestLeafCert(t)
	account := Account{ID: "https://example.com/acct/1", Key: key}

	if err = (Client{}).RevokeCert(context.Background(), account, nil, RevocationReasonUnspecified); err == nil {
		t.Error("RevokeCert accepted a nil certificate")
	}
	ca := *cert
	ca.IsCA = true
	if err = (Client{}).RevokeCert(context.Background(), account, &ca, RevocationReasonUnspecified); err == nil || !strings.Contains(err.Error(), "CA certificate") {
		t.Errorf("error = %v, want CA certificate error", err)
	}

	srv := fixtures.NewServer(t)
	srv.Respond(http.MethodPost, "/revoke", fixtures.Response{Status: http.StatusOK})
	c := Client{
		Dir: ACMEDirectory{
			NewNonce:   srv.Endpoint("newNonce"),
			RevokeCert: srv.Endpoint("revoke"),
		},
		cache: new(nonceCache),
	}
	if err = c.RevokeCert(context.Background(), account, cert, RevocationReasonKeyCompromise); err != nil {
		t.Fatal(err)
	}

	jws := srv.LastRequest(http.MethodPost, "/revoke").JWS(t)
	var req struct {
		Certificate string           `json:"certificate"`
		Reason      RevocationReason `json:"reason"`
	}
	if err = json.Unmarshal(jws.Payload, &req); err != nil {
		t.Fatal(err)
	}
	if want := base64.RawURLEncoding.EncodeToString(cert.Raw); req.Certificate != want {
		t.Error("revocation payload has the wrong certificate")
	}
	if req.Reason != RevocationReasonKeyCompromise {
		t.Errorf("revocation reason = %d, want %d", req.Reason, RevocationReasonKeyCompromise)
	}

	var hdr struct {
		URL   string `json:"url"`
		Nonce string `json:"nonce"`
	}
	if err = json.Unmarshal(jws.ProtectedJSON, &hdr); err != nil {
		t.Fatal(err)
	}
	if hdr.URL != srv.Endpoint("revoke") || hdr.Nonce != fixtures.DefaultNonce {
		t.Errorf("protected header = %+v", hdr)
	}
}
