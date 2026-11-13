package acme

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"net"
	"slices"
	"time"
)

const DefaultInterval = 5 * time.Second

type dnsChallengeState uint32

const (
	dnsChallengeStateInitial dnsChallengeState = iota
	dnsChallengeStateProvisioned
	dnsChallengeStatePending
	dnsChallengeStateValid
	dnsChallengeStateErrorUnprovisioned
	dnsChallengeStateError
)

type DNS01Challenge struct {
	Account    Account
	ExpiresAt  time.Time
	Identifier Identifier
	URL        string
	Status     ChallengeStatus
	Validated  time.Time
	Challenge  Challenge
	IsWildcard bool
	Provider
	// Interval is the default time to wait between calls to the acme server; if the acme response
	// includes a Retry-After header, this value is ignored. A default value of 5 seconds is used;
	// to poll continuously (with no interruption), set this to a negative value (not recommended).
	Interval time.Duration
	dnsChallengeState
	retryAfter time.Time
	closed     bool
	cleanup    CleanupFunc
}

func NewDNS01Challenge(authz Authz, a Account, provider Provider) (DNS01Challenge, error) {
	if authz.Status != AuthzStatusPending {
		// todo: figure out what to do when the status is valid
		return DNS01Challenge{}, errors.New("feck")
	}

	return DNS01Challenge{}, nil
}

func (c *Client) Poll(ctx context.Context, d *DNS01Challenge) (done bool, err error) {
	if d.closed {
		return done, errors.New("cannot poll closed challenge")
	}
	if time.Now().After(d.ExpiresAt) {
		return done, errors.New("authz has expired")
	}

	switch d.dnsChallengeState {
	case dnsChallengeStateInitial:
		if d.cleanup, err = d.Provider.Provision(ctx, TxtRecord{}); err != nil {
			d.dnsChallengeState = dnsChallengeStateErrorUnprovisioned
			return done, err
		}
		d.dnsChallengeState++
	case dnsChallengeStateProvisioned:
		// todo: confirm
		var r net.Resolver

		records, err := r.LookupTXT(ctx, "TODO")
		if err != nil {
			d.dnsChallengeState = dnsChallengeStateError
			return done, err
		}

		_ = records
		// check if the record contains whatever
		if len(records) > 0 {
			d.dnsChallengeState++
		}

	case dnsChallengeStatePending:

		wait := time.Until(d.retryAfter)
		if wait > 0 {
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				d.dnsChallengeState = dnsChallengeStateError
				return done, ctx.Err()
			}
		}

		rc, err := c.FetchRawChallenge(ctx, d.URL, d.Account)
		if err != nil {
			return false, err
		}
		switch rc.Status {
		case ChallengeStatusPending, ChallengeStatusProcessing:
			if rc.RetryAfter.IsZero() {
				if d.Interval == 0 {
					// choose default
					d.retryAfter = time.Now().Add(DefaultInterval)
				} else if d.Interval > 0 {
					d.retryAfter = time.Now().Add(d.Interval)
				}
			} else {
				d.retryAfter = rc.RetryAfter
			}

		case ChallengeStatusValid:
			done = true
			d.dnsChallengeState++
		case ChallengeStatusInvalid:
			d.dnsChallengeState = dnsChallengeStateError
			err = errors.New("challenge concluded as invalid")
		default:
			d.dnsChallengeState = dnsChallengeStateError
			err = errors.New("unknown challenge status")
		}

	case dnsChallengeStateValid:
		done = true

	case dnsChallengeStateError, dnsChallengeStateErrorUnprovisioned:
		return done, errors.New("previous calls returned an error")
	default:
		return done, errors.New("invalid dns challenge state")
	}

	return done, err
}

func (d *DNS01Challenge) Close(ctx context.Context) error {
	if d.closed {
		return nil
	}

	d.closed = true

	if d.cleanup == nil {
		return nil
	}

	return d.cleanup(ctx)
}

type RawChallenge struct {
	Type       string          `json:"type"`
	URL        string          `json:"url"`
	Status     ChallengeStatus `json:"status"`
	Token      string          `json:"token"`
	RetryAfter time.Time       `json:"-"`
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

func (c ChallengeStatus) isValid() bool {
	return c < challengeStatusUnknown
}

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

// returns true if c is a terminal status (i.e., not processing or pending)
func (c ChallengeStatus) isDone() bool {
	return !(c == ChallengeStatusPending || c == ChallengeStatusProcessing)
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
