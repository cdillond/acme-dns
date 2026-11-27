package acme

import (
	"encoding/json/jsontext"
	"errors"
	"slices"
	"time"
)

type AccountStatus uint32

const (
	accountStatusUnspecified AccountStatus = iota
	AccountStatusValid
	AccountStatusDeactivated
	AccountStatusRevoked
	accountStatusUnknown
)

var accountStrings = [accountStatusUnknown]string{
	"",
	"valid",
	"deactivated",
	"revoked",
}

func newAccountStatus(s string) AccountStatus {
	n := slices.Index(accountStrings[:], s)

	if n == -1 {
		return accountStatusUnknown
	}

	return AccountStatus(n)
}

func (a AccountStatus) String() string {
	if a >= accountStatusUnknown {
		return "unknown"
	}

	return accountStrings[a]
}

func (a *AccountStatus) MarshalJSONTo(enc *jsontext.Encoder) error {
	return enc.WriteToken(jsontext.String(a.String()))
}

func (a *AccountStatus) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	tok, err := dec.ReadToken()
	if err != nil {
		return err
	}
	if tok.Kind() != jsontext.KindString {
		return errors.New("invalid order status serialisation: " + tok.String())
	}

	s := tok.String()

	*a = newAccountStatus(s)

	return nil
}

// An [AccountCfg] contains optional parameters for account registration.
type AccountCfg struct {
	// A slice of contacts. These strings must be in a format accepted by the ACME server.
	// For example, Let's Encrypt accepts contacts in the form "mailto:foo@example.com".
	Contact []string `json:"contact,omitempty"`
	// Indicates whether the user agrees to the terms of service. CAs are free to disregard this field.
	// If terms of service agreement is required by the CA, the terms of service can be found at the URL
	// named by the [Client.Dir.Meta.TermsOfService] field.
	TermsOfServiceAgreed bool `json:"termsOfServiceAgreed,omitzero"`
	// If true, the ACME server will not create a new account and instead return an error if
	// an account for a specified key does not already exist.
	OnlyReturnExisting bool `json:"onlyReturnExisting,omitzero"`
}

// An [Account] represents an account registered with an ACME server.
type Account struct {
	ID  string
	Key AccountKey
}

// [AccountData] represents the data associated with an account as returned by an ACME server.
// The server is not required to return all fields, so, with the exception of
// [AccountData.Status], it should be regarded as informational.
type AccountData struct {
	Status                 AccountStatus          `json:"status"`
	CreatedAt              time.Time              `json:"createdAt"`
	Contact                []string               `json:"contact"`
	ExternalAccountBinding ExternalAccountBinding `json:"externalAccountBinding"`
	TermsOfServiceAgreed   bool                   `json:"termsOfServiceAgreed"`
	Orders                 string                 `json:"orders"`
}
