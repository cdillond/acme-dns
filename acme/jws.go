package acme

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"math/big"
)

// jwk is the public half of an ES256 key, as embedded in the "jwk" member of a
// JWS protected header.
type jwk struct {
	Crv string `json:"crv"`
	Kty string `json:"kty"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func (e ES256Key) jwk() (jwk, error) {
	if e.pk == nil {
		return jwk{}, errors.New("uninitialized ES256Key")
	}

	// SEC 1 uncompressed point: 0x04 || X || Y. P-256 coordinates are 32 bytes.
	point, err := e.pk.PublicKey.Bytes()
	if err != nil {
		return jwk{}, err
	}
	if len(point) != 65 || point[0] != 0x04 {
		return jwk{}, errors.New("unexpected public key encoding")
	}

	return jwk{
		Crv: "P-256",
		Kty: "EC",
		X:   base64.RawURLEncoding.EncodeToString(point[1:33]),
		Y:   base64.RawURLEncoding.EncodeToString(point[33:65]),
	}, nil
}

// thumbprint returns the RFC 7638 SHA-256 thumbprint of the JWK.
func (k jwk) thumbprint() ([sha256.Size]byte, error) {
	if k.Kty != "EC" || k.Crv != "P-256" {
		return [sha256.Size]byte{}, errors.New("invalid ES256 JWK")
	}
	if k.X == "" || k.Y == "" {
		return [sha256.Size]byte{}, errors.New("invalid 256 JWK")
	}

	b, err := json.Marshal(&k, json.Deterministic(true))
	if err != nil {
		return [sha256.Size]byte{}, err
	}

	return sha256.Sum256(b), nil
}

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

func sign(url string, key ES256Key, payload []byte, nonce string) (jwsDto, error) {
	var (
		out       jwsDto
		err       error
		protected []byte
		digest    [32]byte
		r, s      *big.Int
		sig       []byte
		h         = jwsHeader{
			Alg:   "ES256",
			URL:   url,
			Nonce: nonce,
		}
	)

	if key.id == "" {
		if h.JWK, err = key.jwk(); err != nil {
			return out, err
		}
	} else {
		h.KID = key.id
	}

	if protected, err = json.Marshal(h); err != nil {
		return out, err
	}

	out.Protected = base64.RawURLEncoding.EncodeToString(protected)
	out.Payload = base64.RawURLEncoding.EncodeToString(payload)

	digest = sha256.Sum256([]byte(out.Protected + "." + out.Payload))

	if r, s, err = ecdsa.Sign(rand.Reader, key.pk, digest[:]); err != nil {
		return out, err
	}

	// JWS ES256 signatures are the raw fixed-width R || S pair.
	sig = make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])

	out.Sig = base64.RawURLEncoding.EncodeToString(sig)

	return out, nil
}

type jwsHeader struct {
	Alg string `json:"alg"`
	// KID and JWK are mutually exclusive
	KID   string `json:"kid,omitempty"`
	JWK   jwk    `json:"jwk,omitzero"`
	URL   string `json:"url"`
	Nonce string `json:"nonce"`
}
