package acme

import (
	"encoding/json/jsontext"
	"errors"
	"slices"
	"time"
)

type RawChallenge struct {
	Type       string          `json:"type"`
	URL        string          `json:"url"`
	Status     ChallengeStatus `json:"status"`
	Token      string          `json:"token"`
	retryAfter retryAfter      `json:"-"`
}

type Challenge struct {
	Type      string          `json:"type"`
	URL       string          `json:"url"`
	Status    ChallengeStatus `json:"status"`
	Token     string          `json:"token"`
	Validated time.Time       `json:"validated,omitzero"`
	Error     *Problem        `json:"error,omitzero"`
}

type ChallengeStatus uint32

const (
	ChallengeStatusInvalid ChallengeStatus = iota
	ChallengeStatusPending
	ChallengeStatusProcessing
	ChallengeStatusValid
	challengeStatusUnknown
)

var challengeStrings = [challengeStatusUnknown]string{
	"invalid",
	"pending",
	"processing",
	"valid",
}

func NewChallengeStatus(s string) ChallengeStatus {
	n := slices.Index(challengeStrings[:], s)

	if n == -1 {
		return challengeStatusUnknown
	}

	return ChallengeStatus(n)
}

func (c ChallengeStatus) String() string {
	if c >= challengeStatusUnknown {
		return "unknown"
	}

	return challengeStrings[c]
}

func (c *ChallengeStatus) MarshalJSONTo(enc *jsontext.Encoder) error {
	return enc.WriteToken(jsontext.String(c.String()))
}

func (c *ChallengeStatus) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	tok, err := dec.ReadToken()
	if err != nil {
		return err
	}
	if tok.Kind() != jsontext.KindString {
		return errors.New("invalid order status serialisation: " + tok.String())
	}

	s := tok.String()

	*c = NewChallengeStatus(s)

	return nil
}

type UnexpectedChallengeStatusError OrderStatus

func (u UnexpectedChallengeStatusError) Error() string {
	return "unexpected challenge status: " + ChallengeStatus(u).String()
}
