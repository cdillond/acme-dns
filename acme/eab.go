package acme

import (
	"encoding/json/jsontext"
	"hash"
)

// EABRequest contains the external account binding credentials provided by a CA.
//
// Hash must be a keyed MAC (for example, hmac.New(sha256.New, macKey) for HS256),
// not an unkeyed hash. Alg must be the MAC-based JWS algorithm that matches the
// provided MAC, and the CA must support that algorithm.
type EABRequest struct {
	// KID is the key identifier provided by the CA.
	KID string
	// Alg is the MAC-based JWS algorithm, such as "HS256".
	Alg string
	// Hash is the keyed MAC used to sign the external account binding JWS.
	Hash hash.Hash
}

// ExternalAccountBinding holds raw JSON for an ACME external account binding,
// which links an ACME account to an existing account with the CA. It is used by
// CAs that require EAB; most public CAs, including Let's Encrypt, do not.
type ExternalAccountBinding jsontext.Value

// UnmarshalJSONFrom stores the raw EAB JSON value.
func (e *ExternalAccountBinding) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	val, err := dec.ReadValue()
	if err != nil {
		return err
	}

	*e = ExternalAccountBinding(val.Clone())

	return nil
}
