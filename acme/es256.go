package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"

	"github.com/go-jose/go-jose/v4"
)

type ES256Key struct {
	pk         *ecdsa.PrivateKey
	thumbprint []byte
}

func (e ES256Key) Bytes() ([]byte, error) {
	return e.pk.Bytes()
}

func newE256KeyfromECDSA(pk *ecdsa.PrivateKey) (ES256Key, error) {
	jwk := jose.JSONWebKey{
		Key: pk,
	}

	pub := jwk.Public()

	thumbprint, err := pub.Thumbprint(crypto.SHA256)

	if err != nil {
		return ES256Key{}, err
	}

	return ES256Key{
		pk:         pk,
		thumbprint: thumbprint,
	}, nil
}

func NewE256Key() (ES256Key, error) {
	pk, err := ecdsa.GenerateKey(elliptic.P256(), nil)
	if err != nil {
		return ES256Key{}, err
	}

	return newE256KeyfromECDSA(pk)
}

func NewE256KeyFromBytes(b []byte) (ES256Key, error) {
	pk, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), b)
	if err != nil {
		return ES256Key{}, err
	}

	return newE256KeyfromECDSA(pk)
}
