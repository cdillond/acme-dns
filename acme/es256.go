package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"math/big"
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
	pk         *ecdsa.PrivateKey
	thumbprint []byte
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

func (e es256Key) signKID(url, id string, payload []byte, nonce string) ([]byte, error) {
	var (
		b         []byte
		dto       jwsDto
		err       error
		protected []byte
		digest    [32]byte
		r, s      *big.Int
		sig       []byte
		h         = jwsHeaderWithKID{
			KID:   id,
			Alg:   "ES256",
			URL:   url,
			Nonce: nonce,
		}
	)

	if protected, err = json.Marshal(&h); err != nil {
		return b, err
	}

	dto.Protected = base64.RawURLEncoding.EncodeToString(protected)
	dto.Payload = base64.RawURLEncoding.EncodeToString(payload)

	digest = sha256.Sum256([]byte(dto.Protected + "." + dto.Payload))

	if r, s, err = ecdsa.Sign(rand.Reader, e.pk, digest[:]); err != nil {
		return b, err
	}

	// JWS ES256 signatures are the raw fixed-width R || S pair.
	sig = make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])

	dto.Sig = base64.RawURLEncoding.EncodeToString(sig)

	if b, err = json.Marshal(&dto, json.Deterministic(true)); err != nil {
		return b, nil
	}

	return b, nil
}

func (e es256Key) signJWK(url string, payload []byte, nonce string) ([]byte, error) {
	var (
		b         []byte
		dto       jwsDto
		err       error
		protected []byte
		digest    [32]byte
		r, s      *big.Int
		sig       []byte
		h         = jwsHeaderWithJWK{
			Alg:   "ES256",
			URL:   url,
			Nonce: nonce,
		}
	)

	if h.JWK, err = e.jwk(); err != nil {
		return b, err
	}

	if protected, err = json.Marshal(&h, json.Deterministic(true)); err != nil {
		return b, err
	}

	dto.Protected = base64.RawURLEncoding.EncodeToString(protected)
	dto.Payload = base64.RawURLEncoding.EncodeToString(payload)

	digest = sha256.Sum256([]byte(dto.Protected + "." + dto.Payload))

	if r, s, err = ecdsa.Sign(rand.Reader, e.pk, digest[:]); err != nil {
		return b, err
	}

	// JWS ES256 signatures are the raw fixed-width R || S pair.
	sig = make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])

	dto.Sig = base64.RawURLEncoding.EncodeToString(sig)

	if b, err = json.Marshal(&dto, json.Deterministic(true)); err != nil {
		return b, nil
	}

	return b, nil
}
