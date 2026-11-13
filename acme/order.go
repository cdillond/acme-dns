package acme

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
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

	for key := range domains {
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
	retryAfter     time.Time           `json:"-"`
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

func defaultCleanupFn(ctx context.Context) error {
	return nil
}

func checkResolver(ctx context.Context, domain, targ string) (bool, error) {
	r := net.Resolver{
		PreferGo: true,
	}
	s, err := r.LookupTXT(ctx, domain)
	if err != nil {
		fmt.Println(err)
		return false, err
	}

	fmt.Println(s)
	if slices.Contains(s, targ) {
		fmt.Println("found!", s)
		return true, nil
	}
	return false, nil
}

func waitForDns(ctx context.Context, domain, targ string, retries int) {
	found, err := checkResolver(ctx, domain, targ)
	if err != nil {
		return
	}
	if found {
		return
	}

	fmt.Println("waiting")
	ticker := time.NewTicker(5 * time.Second)

	for ; retries > 0; retries-- {
		select {
		case <-ticker.C:
			found, err = checkResolver(ctx, domain, targ)
			if err != nil {
				return
			}
			if found {
				return
			}
			fmt.Println("waiting...", retries)

		case <-ctx.Done():
			return
		}
	}
	fmt.Println("out of retries")
}

func (c *Client) provisionAuthz(ctx context.Context, a Account, az Authz, domains map[string]Provider) (TxtRecord, CleanupFunc, error) {
	dnsChallenge := filterChallenges(az.Challenges)
	if dnsChallenge == nil {
		return TxtRecord{}, nil, errors.New("no dns challenge available for Authz")
	}

	fmt.Printf("\n\ndns challenge\n%#v\n\n", *dnsChallenge)

	n := az.Identifier.Value
	if az.Wildcard {
		n = "*." + n
	}

	p := domains[n]
	if p == nil {
		fmt.Println(az)
		return TxtRecord{}, nil, errors.New("could not find registered provider")
	}

	txt := TxtRecord{
		TTL:  DefaultTTL,
		Name: "_acme-challenge." + az.Identifier.Value,
		Txt:  newDNS01Txt(dnsChallenge.Token, a.ES256Key),
	}

	cleanup, err := p.Provision(ctx, txt)
	if err != nil {
		return TxtRecord{}, nil, err
	}
	if cleanup == nil {
		cleanup = defaultCleanupFn
	}

	return txt, cleanup, nil
}

func (c *Client) validateAuthz(ctx context.Context, a Account, az Authz) error {
	dnsChallenge := filterChallenges(az.Challenges)
	if dnsChallenge == nil {
		return errors.New("no dns challenge available for Authz")
	}

	raw, err := c.AcceptChallenge(ctx, dnsChallenge.URL, a)
	if err != nil {
		return err
	}

	for err == nil && !raw.Status.isDone() {
		wait := time.Until(raw.RetryAfter)
		if wait > 0 {
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		raw, err = c.FetchRawChallenge(ctx, dnsChallenge.URL, a)
	}

	fmt.Printf("\n\nrc: %#v\n", raw)

	if err != nil {
		return err
	}

	switch raw.Status {
	case challengeStatusUnknown:
		err = errors.New("bad challenge status")
	case ChallengeStatusInvalid:
		err = errors.New("challenge failed")
	}

	return err
}

func cleanup(ctx context.Context, fns []CleanupFunc) error {
	var (
		cancel context.CancelFunc
		fn     CleanupFunc
		err    error
	)

	ctx, cancel = context.WithTimeout(
		context.WithoutCancel(ctx),
		10*time.Second,
	)
	defer cancel()

	for _, fn = range fns {
		err = errors.Join(err, fn(ctx))
	}

	return nil
}

func (o *Order) Poll(ctx context.Context, c *Client, a Account) (b []byte, certKey *ecdsa.PrivateKey, err error) {
	var (
		ch   chan error
		az   Authz
		auth []Authz
		url  string
	)

	ctx, cancel := context.WithCancel(ctx)

	defer cancel()

	if auth, err = c.FetchAuthz(ctx, a, *o); err != nil {
		return b, certKey, err
	}

	ch = make(chan error, len(auth))

	var (
		records  []TxtRecord
		cleanups []CleanupFunc
	)

	defer func() {
		err = errors.Join(err, cleanup(ctx, cleanups))
	}()

	for _, az = range auth {
		var (
			txt     TxtRecord
			cleanup CleanupFunc
		)

		if txt, cleanup, err = c.provisionAuthz(ctx, a, az, o.domains); err != nil {
			return b, certKey, err
		}

		records = append(records, txt)
		cleanups = append(cleanups, cleanup)
	}

	for _, txt := range records {
		waitForDns(ctx, txt.Name, txt.Txt, 5)
	}

	for _, az = range auth {
		go func(ctx context.Context, a Account, az Authz) {
			ch <- c.validateAuthz(ctx, a, az)
		}(ctx, a, az)
	}

	for range auth {
		err = errors.Join(err, <-ch)
	}

	if err != nil {
		return b, certKey, err
	}

	if err = c.verifyAuthz(ctx, o.Authorizations, a, 5); err != nil {
		return b, certKey, err
	}

	if err = c.verifyOrderReady(ctx, o, a, 5); err != nil {
		return b, certKey, err
	}

	if certKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		return b, nil, err
	}

	if err = c.finalize(ctx, a, o, certKey); err != nil {
		return b, nil, err
	}

	if url, err = c.awaitURL(ctx, a, o, 6); err != nil {
		return b, nil, err
	}

	b, err = c.downloadCert(ctx, url, a)

	return b, certKey, err
}

func (c *Client) downloadCert(ctx context.Context, url string, a Account) ([]byte, error) {
	var (
		b   []byte
		err error
		res *http.Response
		bad Problem
		dec *jsontext.Decoder
	)

	if res, err = c.signedPostAsGet(ctx, url, a.Location, a.ES256Key); err != nil {
		return b, err
	}

	defer func() {
		err = errors.Join(err, res.Body.Close())
	}()

	if res.StatusCode != http.StatusOK {
		dec = jsontext.NewDecoder(res.Body)
		if err = json.UnmarshalDecode(dec, &bad); err != nil {
			return b, err
		}
		err = &bad
		return b, err
	}

	b, err = io.ReadAll(res.Body)

	return b, err

}

func (c *Client) verifyAuthz(ctx context.Context, urls []string, a Account, retries int) error {
	var (
		authz Authz
		err   error
	)

start:
	if retries <= 0 {
		return errors.New("could not validate all authz")
	}

	for _, u := range urls {
		err = c.fetchUnmarshalAuthz(ctx, u, a.Location, a.ES256Key, &authz)
		if err != nil {
			return err
		}
		switch authz.Status {
		case AuthzStatusValid:
		case AuthzStatusPending:
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Until(authz.retryAfter)):
				retries--
			}
			goto start
		case authzStatusUnknown:
			return errors.New("fecks")
		default:
			return errors.New("feck")
		}
	}

	return nil
}

func (c *Client) awaitURL(ctx context.Context, a Account, o *Order, retries int) (string, error) {
	var err error

	for err = c.fetchOrder(ctx, o, a); err == nil && retries > 0; err = c.fetchOrder(ctx, o, a) {
		if o.CertificateURL != "" {
			return o.CertificateURL, nil
		}
		select {
		case <-time.After(time.Until(o.retryAfter)):
		case <-ctx.Done():
			return "", ctx.Err()
		}

		retries--
	}

	if err != nil {
		return "", err
	}

	return "", errors.New("retries exhausted")

}

func (c *Client) finalize(ctx context.Context, a Account, o *Order, key *ecdsa.PrivateKey) error {
	var (
		err error
		csr csr
		b   []byte
		buf = new(bytes.Buffer)
		enc = jsontext.NewEncoder(buf)
	)

	if csr, err = newCSR(key, slices.Collect(maps.Keys(o.domains))); err != nil {
		return err
	}

	if err = json.MarshalEncode(enc, &csr); err != nil {
		return err
	}

	b = buf.Bytes()

	if err = c.submitFinalize(ctx, o, a, b); err != nil {
		return err
	}

	return nil
}

func (c *Client) submitFinalize(ctx context.Context, o *Order, a Account, b []byte) error {
	var (
		res *http.Response
		err error
		dec *jsontext.Decoder
		bad Problem
	)

	if res, err = c.signedPost(ctx, o.Finalize, a.Location, a.ES256Key, b); err != nil {
		return err
	}

	defer func() {
		err = errors.Join(err, res.Body.Close())
	}()

	dec = jsontext.NewDecoder(res.Body)

	if res.StatusCode != http.StatusOK {
		err = json.UnmarshalDecode(dec, &bad)
		if err != nil {
			return err
		}
		err = &bad
		return err
	}

	err = json.UnmarshalDecode(dec, o)
	if err != nil {
		return err
	}

	switch o.Status {
	case OrderStatusPending:
		// this should not happen because it means not all authz are complete
		return errors.New("not all authz recognized as complete")
	case OrderStatusReady:
		// this should not happen because the finalize request has been received
		// in any case, we will treat this as a recoverable server error
	case OrderStatusProcessing:
		// strictly speaking, this is the only valid response
	case OrderStatusValid:
		// for lets encrypt, this an error will be returned instead of a valid
		// order, but we'll treat it as recoverable, since we aren't implementing
		// a strict state machine
	case OrderStatusInvalid:
		return errors.New("order failed")
	default:
		return errors.New("unknown order status")
	}

	o.retryAfter = parseRetryAfterHeader(res.Header.Get("Retry-After"))
	if o.retryAfter.IsZero() {
		o.retryAfter = time.Now().Add(DefaultInterval)
	}

	return nil
}

func (c *Client) verifyOrderReady(ctx context.Context, o *Order, a Account, retries int) error {
	var err error

	for err = c.fetchOrder(ctx, o, a); err == nil && retries > 0; retries-- {
		switch o.Status {
		case OrderStatusPending:
			// keep polling
		case OrderStatusReady:
			return nil
		case OrderStatusProcessing:
			return errors.New("finalize already called")
		case OrderStatusValid:
			return errors.New("finalize already called")
		case OrderStatusInvalid:
			return errors.New("order failed")
		default:
			return errors.New("uknown order status")
		}

		select {
		case <-time.After(time.Until(o.retryAfter)):
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	if err != nil {
		return err
	}

	return errors.New("retries exhausted")
}

func (c *Client) fetchOrder(ctx context.Context, o *Order, a Account) error {
	var (
		res *http.Response
		err error
		dec *jsontext.Decoder
		bad Problem
	)

	if res, err = c.signedPostAsGet(ctx, o.Location, a.Location, a.ES256Key); err != nil {
		return err
	}

	defer func() {
		err = errors.Join(err, res.Body.Close())
	}()

	dec = jsontext.NewDecoder(res.Body)

	if res.StatusCode != http.StatusOK {
		err = json.UnmarshalDecode(dec, &bad)
		if err != nil {
			return err
		}
		err = &bad
		return err
	}

	err = json.UnmarshalDecode(dec, o)
	if err != nil {
		return err
	}

	switch o.Status {
	case OrderStatusPending:
		return errors.New("not all authz recognized as complete")
	case OrderStatusReady:
	case OrderStatusProcessing:
	case OrderStatusValid:
		if o.CertificateURL == "" {
			return errors.New("order validated, but no certificate URL was provided")
		}
		return nil
	case OrderStatusInvalid:
		return errors.New("order failed")
	default:
		return errors.New("unknown order status")
	}

	o.retryAfter = parseRetryAfterHeader(res.Header.Get("Retry-After"))
	if o.retryAfter.IsZero() {
		o.retryAfter = time.Now().Add(DefaultInterval)
	}

	return nil

}
