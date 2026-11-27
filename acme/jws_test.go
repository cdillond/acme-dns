package acme

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"math/big"
	"testing"
)

func TestJWKThumbprintHasNoTrailingNewline(t *testing.T) {
	k := jwk{Crv: "P-256", Kty: "EC", X: "x", Y: "y"}

	canonical, err := json.Marshal(k, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(canonical)

	got, err := k.appendThumbprint(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want[:]) {
		t.Fatalf("thumbprint = %x, want %x", got, want)
	}
}

func TestJWKThumbprintAppends(t *testing.T) {
	k := jwk{Crv: "P-256", Kty: "EC", X: "x", Y: "y"}
	prefix := []byte("prefix:")

	got, err := k.appendThumbprint(prefix)
	if err != nil {
		t.Fatal(err)
	}
	want, err := k.appendThumbprint(nil)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, append(prefix, want...)) {
		t.Fatalf("thumbprint did not append to dst: %x", got)
	}
}

func TestJWSBytesSignature(t *testing.T) {
	key, err := NewAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	hdr := key.newJWSHeaderWithKID("https://example.com/acme/order", "acct/1", "nonce-1")
	payload := []byte(`{"identifiers":[{"type":"dns","value":"example.com"}]}`)

	b, err := jwsBytes(key.es256Key, hdr, payload)
	if err != nil {
		t.Fatal(err)
	}
	var dto jwsDto
	if err = json.Unmarshal(b, &dto); err != nil {
		t.Fatal(err)
	}
	protected, err := base64.RawURLEncoding.DecodeString(dto.Protected)
	if err != nil {
		t.Fatal(err)
	}
	gotPayload, err := base64.RawURLEncoding.DecodeString(dto.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Errorf("payload = %q, want %q", gotPayload, payload)
	}

	var parsed struct {
		Alg   string `json:"alg"`
		URL   string `json:"url"`
		Nonce string `json:"nonce"`
		KID   string `json:"kid"`
	}
	if err = json.Unmarshal(protected, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Alg != "ES256" || parsed.URL != "https://example.com/acme/order" || parsed.Nonce != "nonce-1" || parsed.KID != "acct/1" {
		t.Errorf("protected header = %+v", parsed)
	}

	sig, err := base64.RawURLEncoding.DecodeString(dto.Sig)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != 64 {
		t.Fatalf("signature length = %d, want 64", len(sig))
	}
	pk, ok := key.PrivateKey().(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("key type = %T", key.PrivateKey())
	}
	digest := sha256.Sum256([]byte(dto.Protected + "." + dto.Payload))
	if !ecdsa.Verify(&pk.PublicKey, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Error("ES256 signature did not verify")
	}
}

func TestSignMAC(t *testing.T) {
	secret := []byte("eab-secret")
	payload := []byte(`{"example":"value"}`)

	dto, err := signMAC("https://example.com/acme/newAccount", "eab-kid", "HS256", hmac.New(sha256.New, secret), payload)
	if err != nil {
		t.Fatal(err)
	}

	protected, err := base64.RawURLEncoding.DecodeString(dto.Protected)
	if err != nil {
		t.Fatal(err)
	}
	var hdr jwsMACHeader
	if err = json.Unmarshal(protected, &hdr); err != nil {
		t.Fatal(err)
	}
	if hdr.Alg != "HS256" || hdr.KID != "eab-kid" || hdr.URL != "https://example.com/acme/newAccount" {
		t.Errorf("protected header = %+v", hdr)
	}

	gotSig, err := base64.RawURLEncoding.DecodeString(dto.Sig)
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(dto.Protected + "." + dto.Payload))
	if !hmac.Equal(gotSig, mac.Sum(nil)) {
		t.Error("EAB MAC did not verify with the provided secret")
	}
}
