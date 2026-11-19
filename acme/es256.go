package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math/big"
)

type AccountKey struct {
	es256Key
}

// NewAccountKey generates a random [ecdsa.PrivateKey] with the NIST P-256 curve
// and returns an [AccountKey] constructed with that key.
func NewAccountKey() (AccountKey, error) {
	k, err := newE256Key()
	if err != nil {
		return AccountKey{}, err
	}
	return AccountKey{es256Key: k}, nil
}

// NewAccountKeyFromECDSAP256 constructs a new [AccountKey] from the supplied [*ecdsa.PrivateKey]. It
// returns a non-nil error if the key's [ecdsa.PrivateKey.Curve] is not [elliptic.P256].
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

	if jwk, err = key.newJWK(); err != nil {
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

func (e es256Key) newJWK() (jwk, error) {
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

func (e es256Key) sign(message []byte) ([]byte, error) {
	var (
		b      []byte
		err    error
		digest [32]byte
		r, s   *big.Int
	)

	digest = sha256.Sum256(message)

	if r, s, err = ecdsa.Sign(rand.Reader, e.pk, digest[:]); err != nil {
		return b, err
	}

	// JWS ES256 signatures are the raw fixed-width R || S pair.
	b = make([]byte, 64)
	r.FillBytes(b[:32])
	s.FillBytes(b[32:])
	return b, nil
}

func (e es256Key) newJWSHeaderWithKID(url, id, nonce string) jwsHeaderWithKID {
	return jwsHeaderWithKID{
		KID:   id,
		Alg:   "ES256",
		URL:   url,
		Nonce: nonce,
	}
}

func (e es256Key) newJWSHeaderWithJWK(url, nonce string) (jwsHeaderWithJWK, error) {
	j, err := e.newJWK()
	if err != nil {
		return jwsHeaderWithJWK{}, err
	}

	return jwsHeaderWithJWK{
		JWK:   j,
		Alg:   "ES256",
		URL:   url,
		Nonce: nonce,
	}, nil
}
