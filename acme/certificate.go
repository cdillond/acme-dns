package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"net/http"
	"time"
)

// Certificate holds a private key and an X509 certificate chain.
// The leaf certificate will always be the initial element of the [Certificate.Chain] field.
// The private key is generated as part of the certificate order. Its concrete type is *ecdsa.PrivateKey,
// but other key types may be supported in the future.
type Certificate struct {
	PrivateKey crypto.PrivateKey
	Chain      []*x509.Certificate
}

// Leaf returns the leaf [*x509.Certificate] in c's [Certificate.Chain]. It returns nil if the chain is empty
// or if the initial certificate in the chain is nil.
func (c Certificate) Leaf() *x509.Certificate {
	if len(c.Chain) < 1 {
		return nil
	}
	return c.Chain[0]
}

// ShouldRenew returns true if the current time is after the leaf certificate's NotBefore and the duration until
// certificate expiration is less than minTimeUntilExpiration. It also returns true if the leaf certificate is nil.
func (c Certificate) ShouldRenew(minTimeUntilExpiration time.Duration) bool {
	l := c.Leaf()
	if l == nil {
		return true
	}
	t := time.Now()
	if t.Before(l.NotBefore) {
		return false
	}
	return t.Add(minTimeUntilExpiration).After(l.NotAfter)
}

// PrivateKeyDER returns the PKCS #8, ASN.1 DER form of the certificate's Key.
func (c Certificate) PrivateKeyDER() ([]byte, error) {
	key, ok := c.PrivateKey.(*ecdsa.PrivateKey)

	if !ok {
		return nil, errors.New("invalid private key")
	}

	return x509.MarshalPKCS8PrivateKey(key)
}

type RevocationReason uint32

const (
	RevocationReasonUnspecified RevocationReason = iota
	RevocationReasonKeyCompromise
	RevocationReasonCACompromise
	RevocationReasonAffiliationChange
	RevocationReasonSuperseded
	RevocationReasonCessationOfOperation
	RevocationReasonHold
	_
	RevocationReasonRemoveFromCRL
	RevocationReasonPrivilegeWithdrawn
	RevocationReasonAACompromise
)

type certRevocationRequest struct {
	Certificate string           `json:"certificate"`
	Reason      RevocationReason `json:"reason"`
}

// RevokeCert revokes a certificate. For a [Certificate] returned from [Client.OrderCertificate], only the
// initial [*x509.Certificate] in [Certificate.Chain] should be revoked.
func (c Client) RevokeCert(ctx context.Context, account Account, cert *x509.Certificate, reason RevocationReason) error {
	var (
		err     error
		payload []byte
		res     *http.Response
		dec     *jsontext.Decoder
		bad     Problem
		r       = certRevocationRequest{
			Certificate: base64.RawURLEncoding.EncodeToString(cert.Raw),
			Reason:      reason,
		}
	)

	if cert.IsCA {
		return errors.New("cannot revoke CA certificate; only revoke the initial cert in a chain")
	}

	if payload, err = json.Marshal(&r); err != nil {
		return err
	}

	if res, err = c.signedPostID(ctx, c.Dir.RevokeCert, account.ID, account.Key.es256Key, payload); err != nil {
		return err
	}

	defer func() {
		err = errors.Join(err, res.Body.Close())
	}()

	if res.StatusCode > 299 {
		dec = jsontext.NewDecoder(res.Body)
		if err = json.UnmarshalDecode(dec, &bad); err != nil {
			return err
		}
		return &bad
	}

	return nil
}
