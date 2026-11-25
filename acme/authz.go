package acme

import (
	"encoding/json/jsontext"
	"errors"
	"slices"
	"time"
)

type FailedChallengeError string

func (f FailedChallengeError) Error() string {
	return "failed: " + string(f)
}

const (
	ErrFailedAccount   FailedChallengeError = "account"
	ErrFailedOrder     FailedChallengeError = "order"
	ErrFailedAuthz     FailedChallengeError = "authz"
	ErrFailedChallenge FailedChallengeError = "challenge"
)

type authz struct {
	Identifier Identifier  `json:"identifier"`
	Status     authzStatus `json:"status"`
	Expires    time.Time   `json:"expires,omitzero"`
	Challenges []challenge `json:"challenges"`
	Wildcard   bool        `json:"wildcard"`
	retryAfter retryAfter  `json:"-"`
}

type authzStatus uint32

const (
	authzStatusInvalid authzStatus = iota
	authzStatusPending
	authzStatusValid
	authzStatusDeactivated
	authzStatusExpired
	authzStatusRevoked
	authzStatusUnknown
)

var authzStrings = [authzStatusUnknown]string{
	"invalid",
	"pending",
	"valid",
	"deactivated",
	"expired",
	"revoked",
}

func partitionAuthz(s []authz) (pending, valid, bad []authz) {
	for _, a := range s {
		switch a.Status {
		case authzStatusPending:
			pending = append(pending, a)
		case authzStatusValid:
			valid = append(valid, a)
		default:
			bad = append(bad, a)
		}
	}
	return pending, valid, bad
}

func newAuthzStatus(s string) authzStatus {
	n := slices.Index(authzStrings[:], s)

	if n == -1 {
		return authzStatusUnknown
	}

	return authzStatus(n)
}

func (a authzStatus) String() string {
	if a >= authzStatusUnknown {
		return "unknown"
	}

	return authzStrings[a]
}

func (a *authzStatus) MarshalJSONTo(enc *jsontext.Encoder) error {
	return enc.WriteToken(jsontext.String(a.String()))
}

func (a *authzStatus) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	tok, err := dec.ReadToken()
	if err != nil {
		return err
	}
	if tok.Kind() != jsontext.KindString {
		return errors.New("invalid order status serialisation: " + tok.String())
	}

	s := tok.String()

	*a = newAuthzStatus(s)

	return nil
}

type UnexpectedAuthzStatusError authzStatus

func (u UnexpectedAuthzStatusError) Error() string {
	return "unexpected authz status: " + authzStatus(u).String()
}
