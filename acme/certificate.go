package acme

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"encoding/pem"
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

// PrivateKeyDER returns the PKCS #8, ASN.1 DER form of the certificate's Key.
func (c Certificate) PrivateKeyDER() ([]byte, error) {
	key, ok := c.PrivateKey.(*ecdsa.PrivateKey)

	if !ok {
		return nil, errors.New("invalid private key")
	}

	return x509.MarshalPKCS8PrivateKey(key)
}

// PrivateKeyPEM returns the PEM-encoded [Certificate.PrivateKey].
func (c Certificate) PrivateKeyPEM() ([]byte, error) {
	der, err := c.PrivateKeyDER()
	if err != nil {
		return nil, err
	}
	buf := new(bytes.Buffer)

	block := pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}

	if err = pem.Encode(buf, &block); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// ChainPEM is a convenience function that returns the [Certificate.Chain] as a PEM-encoded byte slice. Like [pem.EncodeToMemory],
// it returns nil if any of the certificates in the chain are malformed or nil.
func (c Certificate) ChainPEM() []byte {
	var (
		err   error
		cert  *x509.Certificate
		buf   = new(bytes.Buffer)
		block = pem.Block{Type: "CERTIFICATE"}
	)

	for _, cert = range c.Chain {
		if cert == nil {
			return nil
		}

		block.Bytes = cert.Raw

		if err = pem.Encode(buf, &block); err != nil {
			return nil
		}
	}

	return buf.Bytes()
}

// ChainDER is a convenience function that returns the [Certificate.Chain] as a DER-encoded byte slice. If any [*x509.Certificate]
// in the [Certificate.Chain] is nil, it instead returns nil.
func (c Certificate) ChainDER() []byte {
	var (
		b    []byte
		cert *x509.Certificate
	)

	for _, cert = range c.Chain {
		if cert == nil {
			return nil
		}
		b = append(b, cert.Raw...)
	}

	return b
}

// DecodePEM decodes all PEM blocks in b, which must be a PEM-encoded byte slice, and returns the concatenated data from
// the decoded blocks. The output of this function may be passed to, for example, [x509.ParseCertificates].
func DecodePEM(b []byte) []byte {
	var (
		out   []byte = make([]byte, 0, len(b))
		block *pem.Block
	)

	for len(b) > 0 {
		block, b = pem.Decode(b)
		if block == nil {
			break
		}
		out = append(out, block.Bytes...)
	}

	return out
}

// ShouldRenew returns true if the current time is after the leaf certificate's NotBefore and the duration until
// certificate expiration is less than minTimeUntilExpiration. It also returns true if chain is empty or the leaf certificate is nil.
func ShouldRenew(chain []*x509.Certificate, minTimeUntilExpiration time.Duration) bool {
	if len(chain) < 1 {
		return true
	}
	l := chain[0]
	if l == nil {
		return true
	}
	t := time.Now()
	if t.Before(l.NotBefore) {
		return false
	}
	return t.Add(minTimeUntilExpiration).After(l.NotAfter)
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
