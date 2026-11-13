package acme

import (
	"crypto/sha256"
	"encoding/base64"
)

func newKeyAuth(token string, key ES256Key) string {
	out := make([]byte, 0, 128)
	out = append(out, token...)
	out = append(out, '.')
	out = base64.RawURLEncoding.AppendEncode(out, key.thumbprint)
	return string(out)
}

// newDNS01Txt returns the value to provision in the "_acme-challenge" TXT
// record: the base64url encoding of the SHA-256 digest of the key
// authorization (RFC 8555 section 8.4).
func newDNS01Txt(token string, key ES256Key) string {
	sum := sha256.Sum256([]byte(newKeyAuth(token, key)))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
