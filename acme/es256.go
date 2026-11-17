package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
)

type AccountKey struct {
	es256Key
}

func NewAccountKey() (AccountKey, error) {
	k, err := newE256Key()
	if err != nil {
		return AccountKey{}, err
	}
	return AccountKey{es256Key: k}, nil
}

func NewAccountKeyFromECDSAP256(k *ecdsa.PrivateKey) (AccountKey, error) {
	if k.Curve != elliptic.P256() {
		return AccountKey{}, errors.New("unsupported account key type: " + string(k.Curve.Params().Name))
	}
	e, err := newE256KeyFromECDSA(k)
	if err != nil {
		return AccountKey{}, err
	}
	return AccountKey{es256Key: e}, nil
}

func (a AccountKey) PrivateKey() crypto.PrivateKey {
	return a.es256Key.pk
}

type es256Key struct {
	id         string
	pk         *ecdsa.PrivateKey
	thumbprint []byte
}

func (e es256Key) Bytes() ([]byte, error) {
	return e.pk.Bytes()
}

func newE256KeyFromECDSA(pk *ecdsa.PrivateKey) (es256Key, error) {
	var (
		err error
		jwk jwk
		key = es256Key{
			pk: pk,
		}
	)

	if jwk, err = key.jwk(); err != nil {
		return es256Key{}, err
	}

	if key.thumbprint, err = jwk.appendThumbprint(key.thumbprint); err != nil {
		return es256Key{}, err
	}

	return key, nil
}

func newE256Key() (es256Key, error) {
	pk, err := ecdsa.GenerateKey(elliptic.P256(), nil)
	if err != nil {
		return es256Key{}, err
	}

	return newE256KeyFromECDSA(pk)
}
