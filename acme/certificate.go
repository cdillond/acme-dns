package acme

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"net/http"
)

type Certificate struct {
	PrivateKey crypto.PrivateKey
	Chain      []*x509.Certificate
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
func (c Client) RevokeCert(ctx context.Context, cert *x509.Certificate, accountKey AccountKey, reason RevocationReason) error {
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

	if res, err = c.signedPost(ctx, c.dir.RevokeCert, accountKey.es256Key, payload); err != nil {
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
