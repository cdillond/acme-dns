package acme

import (
	"bytes"
	"crypto"
	"encoding/json/jsontext"
	"errors"
	"slices"
	"time"

	"github.com/go-jose/go-jose/v4"
)

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

func NewAccountStatus(s string) AccountStatus {
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

	*a = NewAccountStatus(s)

	return nil
}

type AccountRequest struct {
	ES256Key               `json:"-"`
	Contact                []string               `json:"contact,omitempty"`
	TermsOfServiceAgreed   bool                   `json:"termsOfServiceAgreed"`
	OnlyReturnExisting     bool                   `json:"onlyReturnExisting"`
	ExternalAccountBinding ExternalAccountBinding `json:"externalAccountBinding,omitempty"`
}

func NewAccountRequest(contacts []string, key ES256Key) AccountRequest {
	return AccountRequest{
		ES256Key:               key,
		Contact:                contacts,
		TermsOfServiceAgreed:   true,
		OnlyReturnExisting:     false,
		ExternalAccountBinding: nil,
	}
}

type accountResponse struct {
	Key                    jose.JSONWebKey         `json:"key"`
	Status                 AccountStatus           `json:"status"`
	CreatedAt              time.Time               `json:"createdAt"`
	Contact                *[]string               `json:"contact"`
	ExternalAccountBinding *ExternalAccountBinding `json:"externalAccountBinding"`
	TermsOfServiceAgreed   *bool                   `json:"termsOfServiceAgreed"`
	Orders                 string                  `json:"orders"`
}

func newAccount(req AccountRequest, res accountResponse, loc string) (Account, error) {
	if loc == "" {
		return Account{}, errors.New("invalid location")
	}

	thumb, err := res.Key.Thumbprint(crypto.SHA256)
	if err != nil {
		return Account{}, err
	}
	if !bytes.Equal(req.ES256Key.thumbprint, thumb) {
		return Account{}, errors.New("returned key does not match expected thumbprint")
	}
	if res.Status == accountStatusUnspecified || !res.Status.isValid() {
		return Account{}, errors.New("invalid account status")
	}

	contact := req.Contact
	if res.Contact != nil {
		contact = *res.Contact
	}
	eab := req.ExternalAccountBinding
	if res.ExternalAccountBinding != nil {
		eab = *res.ExternalAccountBinding
	}

	tos := req.TermsOfServiceAgreed
	if res.TermsOfServiceAgreed != nil && tos != *res.TermsOfServiceAgreed {
		return Account{}, errors.New("terms of service agreement mismatch")
	}

	return Account{
		ES256Key: ES256Key{
			id:         loc,
			pk:         req.pk,
			thumbprint: req.thumbprint,
		},
		//Location:               loc,
		CreatedAt:              res.CreatedAt,
		Status:                 res.Status,
		Contact:                contact,
		TermsOfServiceAgreed:   tos,
		ExternalAccountBinding: eab,
		Orders:                 res.Orders,
	}, nil
}

type Account struct {
	ES256Key ES256Key `json:"-"`
	//Location               string                 `json:"-"`
	CreatedAt              time.Time              `json:"createdAt"`
	Status                 AccountStatus          `json:"status"`
	Contact                []string               `json:"contact"`
	TermsOfServiceAgreed   bool                   `json:"termsOfServiceAgreed"`
	ExternalAccountBinding ExternalAccountBinding `json:"externalAccountBinding"`
	Orders                 string                 `json:"orders"`
}
