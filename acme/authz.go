package acme

import (
	"encoding/json/jsontext"
	"errors"
	"slices"
	"time"
)

type Authz struct {
	Identifier Identifier  `json:"identifier"`
	Status     AuthzStatus `json:"status"`
	Expires    time.Time   `json:"expires,omitzero"`
	Challenges []Challenge `json:"challenges"`
	Wildcard   bool        `json:"wildcard"`
}

type AuthzStatus uint32

const (
	AuthzStatusInvalid AuthzStatus = iota
	AuthzStatusPending
	AuthzStatusValid
	AuthzStatusDeactivated
	AuthzStatusExpired
	AuthzStatusRevoked
	authzStatusUnknown
)

func (a AuthzStatus) isValid() bool {
	return a < authzStatusUnknown
}

var authzStrings = [authzStatusUnknown]string{
	"invalid",
	"pending",
	"valid",
	"deactivated",
	"expired",
	"revoked",
}

func NewAuthzStatus(s string) AuthzStatus {
	n := slices.Index(authzStrings[:], s)

	if n == -1 {
		return authzStatusUnknown
	}

	return AuthzStatus(n)
}

func (a AuthzStatus) String() string {
	if a >= authzStatusUnknown {
		return "unknown"
	}

	return authzStrings[a]
}

func (a *AuthzStatus) MarshalJSONTo(enc *jsontext.Encoder) error {
	return enc.WriteToken(jsontext.String(a.String()))
}

func (a *AuthzStatus) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	tok, err := dec.ReadToken()
	if err != nil {
		return err
	}
	if tok.Kind() != jsontext.KindString {
		return errors.New("invalid order status serialisation: " + tok.String())
	}

	s := tok.String()

	*a = NewAuthzStatus(s)

	return nil
}
