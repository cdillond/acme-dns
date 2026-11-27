package acme

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"fmt"
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

func (r *rawChallenge) poll(ctx context.Context, c *Client, id string, key es256Key) error {
	var err error
	switch r.Status {
	case challengeStatusInvalid:
		return joinProblem(errors.Join(ErrFailedChallenge, fmt.Errorf("challenge %q invalid", r.URL)), r.Error)
	case challengeStatusPending, challengeStatusProcessing:
	case challengeStatusValid:
		return nil
	default:
		return UnexpectedChallengeStatusError(r.Status)
	}

	for err = r.fetch(ctx, c, id, key); err == nil; err = r.fetch(ctx, c, id, key) {
		switch r.Status {
		case challengeStatusInvalid:
			return joinProblem(errors.Join(ErrFailedChallenge, fmt.Errorf("challenge %q invalid", r.URL)), r.Error)
		case challengeStatusPending, challengeStatusProcessing:
		case challengeStatusValid:
			return nil
		default:
			return UnexpectedChallengeStatusError(r.Status)
		}

		if err = pause(ctx, r.retryAfter); err != nil {
			return err
		}
	}
	return err
}

func (r *rawChallenge) fetch(ctx context.Context, c *Client, id string, key es256Key) error {
	var err error
	*r, err = c.fetchRawChallenge(ctx, r.URL, id, key)
	return err
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
