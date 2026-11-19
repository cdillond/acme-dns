package acme

import (
	"encoding/json/jsontext"
	"errors"
	"hash"
	"slices"
	"time"
)

type EABRequest struct {
	KID  string
	Alg  string
	Hash hash.Hash
}

type ExternalAccountBinding jsontext.Value

func (e *ExternalAccountBinding) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	val, err := dec.ReadValue()
	if err != nil {
		return err
	}

	*e = ExternalAccountBinding(val.Clone())

	return nil
}

type AccountStatus uint32

const (
	accountStatusUnspecified AccountStatus = iota
	AccountStatusValid
	AccountStatusDeactivated
	AccountStatusRevoked
	accountStatusUnknown
)

func (a AccountStatus) isValid() bool {
	return a < accountStatusUnknown
}

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

type AccountCfg struct {
	Contact              []string `json:"contact,omitempty"`
	TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed,omitzero"`
	OnlyReturnExisting   bool     `json:"onlyReturnExisting,omitzero"`
	//ExternalAccountBinding ExternalAccountBinding `json:"externalAccountBinding,omitempty"`
}

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

type accountResponse struct {
	Status                 AccountStatus           `json:"status"`
	CreatedAt              time.Time               `json:"createdAt"`
	Contact                *[]string               `json:"contact"`
	ExternalAccountBinding *ExternalAccountBinding `json:"externalAccountBinding"`
	TermsOfServiceAgreed   *bool                   `json:"termsOfServiceAgreed"`
	Orders                 string                  `json:"orders"`
}

func newAccountData(cfg AccountCfg, res accountResponse) (AccountData, error) {

	if res.Status == accountStatusUnspecified || !res.Status.isValid() {
		return AccountData{}, errors.New("invalid account status")
	}

	contact := cfg.Contact
	if res.Contact != nil {
		contact = *res.Contact
	}
	var eab ExternalAccountBinding
	//eab := cfg.ExternalAccountBinding
	if res.ExternalAccountBinding != nil {
		eab = *res.ExternalAccountBinding
	}

	tos := cfg.TermsOfServiceAgreed
	if res.TermsOfServiceAgreed != nil && tos != *res.TermsOfServiceAgreed {
		return AccountData{}, errors.New("terms of service agreement mismatch")
	}

	return AccountData{
		CreatedAt:              res.CreatedAt,
		Status:                 res.Status,
		Contact:                contact,
		TermsOfServiceAgreed:   tos,
		ExternalAccountBinding: eab,
		Orders:                 res.Orders,
	}, nil
}
