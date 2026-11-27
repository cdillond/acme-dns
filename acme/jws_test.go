package acme

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
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

const (
	// ECDSA P-256 key and public coordinates from go/x/crypto/acme's test vectors.
	referenceECKeyPEM = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIK07hGLr0RwyUdYJ8wbIiBS55CjnkMD23DWr+ccnypWLoAoGCCqGSM49
AwEHoUQDQgAE5lhEug5xK4xBDZ2nAbaxLtaLiv85bxJ7ePd1dkO23HThqIrvawF5
QAaS/RNouybCiRhRjI3EaxLkQwgrCw0gqQ==
-----END EC PRIVATE KEY-----
`
	referenceECX = "5lhEug5xK4xBDZ2nAbaxLtaLiv85bxJ7ePd1dkO23HQ"
	referenceECY = "4aiK72sBeUAGkv0TaLsmwokYUYyNxGsS5EMIKwsNIKk"

	// RFC 7638 EC JWK thumbprint for the key above.
	referenceThumbprint = "zedj-Bd1Zshp8KLePv2MB-lJ_Hagp7wAwdkA0NUTniU"

	// JWS with payload {"Msg":"Hello JWS"}, nonce "nonce", and url "url".
	referencePayloadB64         = "eyJNc2ciOiJIZWxsbyBKV1MifQ"
	referenceKIDProtected       = "eyJraWQiOiJodHRwczovL2V4YW1wbGUub3JnL2FjY291bnQvMSIsImFsZyI6IkVTMjU2IiwidXJsIjoidXJsIiwibm9uY2UiOiJub25jZSJ9"
	referenceJWKProtected       = "eyJqd2siOnsiY3J2IjoiUC0yNTYiLCJrdHkiOiJFQyIsIngiOiI1bGhFdWc1eEs0eEJEWjJuQWJheEx0YUxpdjg1YnhKN2VQZDFka08yM0hRIiwieSI6IjRhaUs3MnNCZVVBR2t2MFRhTHNtd29rWVVZeU54R3NTNUVNSUt3c05JS2sifSwiYWxnIjoiRVMyNTYiLCJ1cmwiOiJ1cmwiLCJub25jZSI6Im5vbmNlIn0"
	referenceNoncelessProtected = "eyJhbGciOiJFUzI1NiIsImp3ayI6eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6IjVsaEV1ZzV4SzR4QkRaMm5BYmF4THRhTGl2ODVieEo3ZVBkMWRrTzIzSFEiLCJ5IjoiNGFpSzcyc0JlVUFHa3YwVGFMc213b2tZVVl5TnhHc1M1RU1JS3dzTklLayJ9LCJ1cmwiOiJ1cmwifQ"

	// RFC 7520 section 4.4.3 HMAC key, payload, and signature, adapted to this
	// package's jwsMACHeader field order and URL field.
	referenceMACKey     = "hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg"
	referenceMACPayload = "SXTigJlzIGEgZGFuZ2Vyb3VzIGJ1c2luZXNzLCBGcm9kbywgZ29pbmcgb3V0IHlvdXIgZG9vci4gWW91IHN0ZXAgb250byB0aGUgcm9hZCwgYW5kIGlmIHlvdSBkb24ndCBrZWVwIHlvdXIgZmVldCwgdGhlcmXigJlzIG5vIGtub3dpbmcgd2hlcmUgeW91IG1pZ2h0IGJlIHN3ZXB0IG9mZiB0by4"
	referenceMACSig     = "Ubd151q6_ofxKOexo7QW0_7xiXrGkFVK1aTMzkis0RQ"
)

func referenceAccountKey(t *testing.T) AccountKey {
	t.Helper()

	block, _ := pem.Decode([]byte(referenceECKeyPEM))
	if block == nil {
		t.Fatal("failed to decode reference EC key PEM")
	}
	pk, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	key, err := NewAccountKeyFromECDSAP256(pk)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func requireJWSVector[T jwsHeader](t *testing.T, key AccountKey, header T, wantProtected string) {
	t.Helper()

	payload := []byte(`{"Msg":"Hello JWS"}`)
	b, err := jwsBytes(key.es256Key, header, payload)
	if err != nil {
		t.Fatal(err)
	}
	var dto jwsDto
	if err = json.Unmarshal(b, &dto); err != nil {
		t.Fatal(err)
	}
	if dto.Protected != wantProtected {
		t.Errorf("protected = %q, want %q", dto.Protected, wantProtected)
	}
	if dto.Payload != referencePayloadB64 {
		t.Errorf("payload = %q, want %q", dto.Payload, referencePayloadB64)
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

func TestJWKThumbprintKnownVector(t *testing.T) {
	k := jwk{Crv: "P-256", Kty: "EC", X: referenceECX, Y: referenceECY}
	got, err := k.appendThumbprint(nil)
	if err != nil {
		t.Fatal(err)
	}
	if encoded := base64.RawURLEncoding.EncodeToString(got); encoded != referenceThumbprint {
		t.Errorf("thumbprint = %q, want %q", encoded, referenceThumbprint)
	}
}

func TestJWSBytesKnownVector(t *testing.T) {
	key := referenceAccountKey(t)
	j, err := key.newJWK()
	if err != nil {
		t.Fatal(err)
	}
	if j.Crv != "P-256" || j.Kty != "EC" || j.X != referenceECX || j.Y != referenceECY {
		t.Fatalf("reference JWK = %+v", j)
	}

	t.Run("kid", func(t *testing.T) {
		hdr := key.newJWSHeaderWithKID("url", "https://example.org/account/1", "nonce")
		requireJWSVector(t, key, hdr, referenceKIDProtected)
	})

	t.Run("jwk", func(t *testing.T) {
		hdr, err := key.newJWSHeaderWithJWK("url", "nonce")
		if err != nil {
			t.Fatal(err)
		}
		requireJWSVector(t, key, hdr, referenceJWKProtected)
	})

	t.Run("nonceless", func(t *testing.T) {
		hdr, err := key.newJWSHeaderNonceless("url")
		if err != nil {
			t.Fatal(err)
		}
		requireJWSVector(t, key, hdr, referenceNoncelessProtected)
	})
}

func TestSignMACKnownVector(t *testing.T) {
	secret, err := base64.RawURLEncoding.DecodeString(referenceMACKey)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("It’s a dangerous business, Frodo, going out your door. You step onto the road, and if you don't keep your feet, there’s no knowing where you might be swept off to.")

	dto, err := signMAC("", "018c0ae5-4d9b-471b-bfd6-eef314bc7037", "HS256", hmac.New(sha256.New, secret), payload)
	if err != nil {
		t.Fatal(err)
	}
	if dto.Protected != "eyJhbGciOiJIUzI1NiIsInVybCI6IiIsImtpZCI6IjAxOGMwYWU1LTRkOWItNDcxYi1iZmQ2LWVlZjMxNGJjNzAzNyJ9" {
		t.Errorf("protected = %q", dto.Protected)
	}
	if dto.Payload != referenceMACPayload {
		t.Errorf("payload = %q, want %q", dto.Payload, referenceMACPayload)
	}
	if dto.Sig != referenceMACSig {
		t.Errorf("signature = %q, want %q", dto.Sig, referenceMACSig)
	}
}
