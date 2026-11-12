package acme

import (
	"context"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"slices"
	"time"
)

type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type OrderStatus uint32

const (
	OrderStatusInvalid OrderStatus = iota
	OrderStatusPending
	OrderStatusReady
	OrderStatusProcessing
	OrderStatusValid
	orderStatusUnknown
)

func (o OrderStatus) isValid() bool {
	return o < orderStatusUnknown
}

var orderStrings = [orderStatusUnknown]string{
	"invalid",
	"pending",
	"ready",
	"processing",
	"valid",
}

func NewOrderStatus(s string) OrderStatus {
	n := slices.Index(orderStrings[:], s)

	if n == -1 {
		return orderStatusUnknown
	}

	return OrderStatus(n)
}

func (o OrderStatus) String() string {
	if o >= orderStatusUnknown {
		return "unknown"
	}

	return orderStrings[o]
}

func (o *OrderStatus) MarshalJSONTo(enc *jsontext.Encoder) error {
	return enc.WriteToken(jsontext.String(o.String()))
}

func (o *OrderStatus) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	tok, err := dec.ReadToken()
	if err != nil {
		return err
	}
	if tok.Kind() != jsontext.KindString {
		return errors.New("invalid order status serialisation: " + tok.String())
	}

	s := tok.String()

	*o = NewOrderStatus(s)

	return nil
}

type OrderRequest struct {
	Domains   map[string]Provider
	NotBefore time.Time
	NotAfter  time.Time
}

func identifiers(domains map[string]Provider) []Identifier {
	out := make([]Identifier, 0, len(domains))

	for key, _ := range domains {
		out = append(out, Identifier{
			Type:  "dns",
			Value: key,
		})
	}
	return out
}

func (o *OrderRequest) toDto() orderRequest {

	return orderRequest{
		Identifiers: identifiers(o.Domains),
		NotBefore:   o.NotBefore,
		NotAfter:    o.NotAfter,
	}
}

type orderRequest struct {
	Identifiers []Identifier `json:"identifiers"`
	NotBefore   time.Time    `json:"notBefore,omitzero"`
	NotAfter    time.Time    `json:"notAfter,omitzero"`
}

type Order struct {
	// Location is the order's URL, taken from the Location header of the
	// newOrder response. It is needed to poll and finalize the order.
	Location       string              `json:"-"`
	Status         OrderStatus         `json:"status"`
	Expires        time.Time           `json:"expires"`
	Identifiers    []Identifier        `json:"identifiers"`
	NotBefore      time.Time           `json:"notBefore"`
	NotAfter       time.Time           `json:"notAfter"`
	Authorizations []string            `json:"authorizations"`
	Finalize       string              `json:"finalize"`
	CertificateURL string              `json:"certificate"`
	Error          *Problem            `json:"error,omitzero"`
	domains        map[string]Provider `json:"-"`
}

func filterChallenges(src []Challenge) *Challenge {
	for i := range src {
		if src[i].Type == "dns-01" {
			return &src[i]
		}
	}
	return nil
}

type challengeResult struct {
	domain string
	err    error
}

func pollAuthz(ctx context.Context, c *Client, a Account, az Authz, ch chan challengeResult) {
	res := challengeResult{
		domain: az.Identifier.Value,
	}

	dnsChallenge := filterChallenges(az.Challenges)
	if dnsChallenge == nil {
		res.err = errors.New("no dns challenge available for Authz")
		ch <- res
	}

	raw, err := c.FetchRawChallenge(ctx, dnsChallenge.URL, a)
	if err != nil {
		res.err = err
		ch <- res
	}

	fmt.Printf("\nraw challenge\n%#v\n%#v\n\n", raw, az)

	_ = raw

	// todo: implement a state machine for the challenge
	ch <- res
}

func (o *Order) Poll(ctx context.Context, c *Client, a Account) error {
	var (
		ch   chan challengeResult
		az   Authz
		auth []Authz
		err  error
	)

	ctx, cancel := context.WithCancel(ctx)

	defer cancel()

	if auth, err = c.FetchAuthz(ctx, a, *o); err != nil {
		return err
	}

	ch = make(chan challengeResult, len(auth))

	for _, az = range auth {
		go pollAuthz(ctx, c, a, az, ch)
	}

	results := make([]challengeResult, len(auth))

	var bad bool

	for i := range len(auth) {
		select {
		case results[i] = <-ch:
			if results[i].err != nil {
				bad = true
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	_ = bad

	return nil
}
