package acme

import "encoding/base64"

func newKeyAuth(token string, key ES256Key) string {
	out := make([]byte, 0, 128)
	out = append(out, token...)
	out = append(out, '.')
	out = base64.RawURLEncoding.AppendEncode(out, key.thumbprint)
	return string(out)
}
