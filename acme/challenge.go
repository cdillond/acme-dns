package acme

import (
	"encoding/json/jsontext"
	"errors"
	"slices"
	"time"
)

type rawChallenge struct {
	Type       string          `json:"type"`
	URL        string          `json:"url"`
	Status     challengeStatus `json:"status"`
	Token      string          `json:"token"`
	Error      *Problem        `json:"error,omitzero"`
	retryAfter retryAfter      `json:"-"`
}

type challenge struct {
	Type      string          `json:"type"`
	URL       string          `json:"url"`
	Status    challengeStatus `json:"status"`
	Token     string          `json:"token"`
	Validated time.Time       `json:"validated,omitzero"`
	Error     *Problem        `json:"error,omitzero"`
}

type challengeStatus uint32

const (
	challengeStatusInvalid challengeStatus = iota
	challengeStatusPending
	challengeStatusProcessing
	challengeStatusValid
	challengeStatusUnknown
)

var challengeStrings = [challengeStatusUnknown]string{
	"invalid",
	"pending",
	"processing",
	"valid",
}

func newChallengeStatus(s string) challengeStatus {
	n := slices.Index(challengeStrings[:], s)

	if n == -1 {
		return challengeStatusUnknown
	}

	return challengeStatus(n)
}

func (c challengeStatus) String() string {
	if c >= challengeStatusUnknown {
		return "unknown"
	}

	return challengeStrings[c]
}

func (c *challengeStatus) MarshalJSONTo(enc *jsontext.Encoder) error {
	return enc.WriteToken(jsontext.String(c.String()))
}

func (c *challengeStatus) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	tok, err := dec.ReadToken()
	if err != nil {
		return err
	}
	if tok.Kind() != jsontext.KindString {
		return errors.New("invalid order status serialisation: " + tok.String())
	}

	s := tok.String()

	*c = newChallengeStatus(s)

	return nil
}

type UnexpectedChallengeStatusError challengeStatus

func (u UnexpectedChallengeStatusError) Error() string {
	return "unexpected challenge status: " + challengeStatus(u).String()
}
