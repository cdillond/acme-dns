package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
)

type ES256Key struct {
	id         string
	pk         *ecdsa.PrivateKey
	thumbprint []byte
}

func (e ES256Key) Bytes() ([]byte, error) {
	return e.pk.Bytes()
}

func newE256KeyFromECDSA(pk *ecdsa.PrivateKey) (ES256Key, error) {
	key := ES256Key{pk: pk}

	jwk, err := key.jwk()
	if err != nil {
		return ES256Key{}, err
	}

	thumbprint, err := jwk.thumbprint()
	if err != nil {
		return ES256Key{}, err
	}
	key.thumbprint = thumbprint[:]

	return key, nil
}

func NewE256Key() (ES256Key, error) {
	pk, err := ecdsa.GenerateKey(elliptic.P256(), nil)
	if err != nil {
		return ES256Key{}, err
	}

	return newE256KeyFromECDSA(pk)
}

func NewE256KeyFromBytes(b []byte) (ES256Key, error) {
	pk, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), b)
	if err != nil {
		return ES256Key{}, err
	}

	return newE256KeyFromECDSA(pk)
}
