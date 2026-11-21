package acme

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"hash"
)

// jwk is the public half of an ES256 key, as embedded in the "jwk" member of a
// JWS protected header.
type jwk struct {
	Crv string `json:"crv"`
	Kty string `json:"kty"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// append thumbprint appends the RFC 7638 SHA-256 thumbprint of the JWK to dst and returns it.
func (k jwk) appendThumbprint(dst []byte) ([]byte, error) {
	var (
		h   = sha256.New()
		enc = jsontext.NewEncoder(h)
		err = json.MarshalEncode(enc, &k, json.Deterministic(true))
	)

	if err != nil {
		return dst, err
	}

	return h.Sum(dst), nil
}

type jwsDto struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Sig       string `json:"signature"`
}

type jwsHeaderRequiredFields struct {
	Alg   string `json:"alg"`
	URL   string `json:"url"`
	Nonce string `json:"nonce"`
}

type jwsHeaderWithKID struct {
	KID string `json:"kid"`
	jwsHeaderRequiredFields
}

type jwsHeaderWithJWK struct {
	JWK jwk `json:"jwk"`
	jwsHeaderRequiredFields
}

type jwsHeaderNonceless struct {
	Alg string `json:"alg"`
	JWK jwk    `json:"jwk"`
	URL string `json:"url"`
}

type jwsHeader interface {
	jwsHeaderWithJWK | jwsHeaderWithKID | jwsHeaderNonceless
}

func jwsBytes[T jwsHeader](key es256Key, h T, payload []byte) ([]byte, error) {
	var (
		b         []byte
		protected []byte
		err       error
		dto       jwsDto
	)

	if protected, err = json.Marshal(&h, json.Deterministic(true)); err != nil {
		return nil, err
	}

	dto.Protected = base64.RawURLEncoding.EncodeToString(protected)
	dto.Payload = base64.RawURLEncoding.EncodeToString(payload)

	if b, err = key.sign([]byte(dto.Protected + "." + dto.Payload)); err != nil {
		return nil, err
	}

	dto.Sig = base64.RawURLEncoding.EncodeToString(b)

	if b, err = json.Marshal(&dto, json.Deterministic(true)); err != nil {
		return b, err
	}

	return b, nil
}

type jwsMACHeader struct {
	Alg string `json:"alg"`
	URL string `json:"url"`
	KID string `json:"kid"`
}

func signMAC(url, id, alg string, hash hash.Hash, payload []byte) (jwsDto, error) {
	var (
		out       jwsDto
		err       error
		protected []byte
		h         = jwsMACHeader{
			Alg: alg,
			URL: url,
			KID: id,
		}
	)

	if protected, err = json.Marshal(&h); err != nil {
		return out, err
	}

	out.Protected = base64.RawURLEncoding.EncodeToString(protected)
	out.Payload = base64.RawURLEncoding.EncodeToString(payload)

	if _, err = hash.Write([]byte(out.Protected + "." + out.Payload)); err != nil {
		return out, err
	}

	out.Sig = base64.RawURLEncoding.EncodeToString(hash.Sum(nil))

	return out, nil
}
