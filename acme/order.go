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

type UnexpectedOrderStatusError OrderStatus

func (u UnexpectedOrderStatusError) Error() string {
	return "unexpected order status: " + OrderStatus(u).String()
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
	Status         OrderStatus  `json:"status"`
	Expires        time.Time    `json:"expires"`
	Identifiers    []Identifier `json:"identifiers"`
	NotBefore      time.Time    `json:"notBefore"`
	NotAfter       time.Time    `json:"notAfter"`
	Authorizations []string     `json:"authorizations"`
	Finalize       string       `json:"finalize"`
	CertificateURL string       `json:"certificate"`
	Error          *Problem     `json:"error,omitzero"`

	location   string              `json:"-"`
	client     *Client             `json:"-"`
	account    *Account            `json:"-"`
	domains    map[string]Provider `json:"-"`
	retryAfter retryAfter          `json:"-"`
}

func filterChallenges(src []Challenge) *Challenge {
	for i := range src {
		if src[i].Type == "dns-01" {
			return &src[i]
		}
	}
	return nil
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

func (c *Client) provisionAuthz(ctx context.Context, key ES256Key, az Authz, domains map[string]Provider) (TxtRecord, CleanupFunc, error) {
	dnsChallenge := filterChallenges(az.Challenges)
	if dnsChallenge == nil {
		return TxtRecord{}, nil, errors.New("no dns challenge available for Authz")
	}

	n := az.Identifier.Value
	if az.Wildcard {
		n = "*." + n
	}

	p := domains[n]
	if p == nil {
		return TxtRecord{}, nil, errors.New("could not find registered provider")
	}

	txt := TxtRecord{
		TTL:  DefaultTTL,
		Name: "_acme-challenge." + az.Identifier.Value,
		Txt:  newDNS01Txt(dnsChallenge.Token, key),
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

func (c *Client) validateAuthz(ctx context.Context, key ES256Key, az Authz) error {
	dnsChallenge := filterChallenges(az.Challenges)
	if dnsChallenge == nil {
		return errors.New("no dns challenge available for Authz")
	}

	raw, err := c.acceptChallenge(ctx, dnsChallenge.URL, key)
	if err != nil {
		return err
	}

	for err == nil {
		switch raw.Status {
		case ChallengeStatusProcessing:
			// keep polling; no retry limit
		case ChallengeStatusValid:
			return nil
		case ChallengeStatusInvalid:
			return ErrFailedChallenge
		default:
			return UnexpectedChallengeStatusError(raw.Status)
		}

		if err = pause(ctx, raw.retryAfter); err != nil {
			return err
		}

		raw, err = c.fetchRawChallenge(ctx, dnsChallenge.URL, key)
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

func (o *Order) Attempt(ctx context.Context) (b []byte, certKey *ecdsa.PrivateKey, err error) {
	var (
		key      ES256Key
		ch       chan error
		az       Authz
		auth     []Authz
		url      string
		txt      TxtRecord
		fn       CleanupFunc
		records  []TxtRecord
		cleanups []CleanupFunc
		i        int
		c        = o.client
		domains  = slices.Collect(maps.Keys(o.domains))
	)

	if c == nil {
		return b, certKey, errors.New("improperly initialized order")
	}

	if o.account == nil {
		return b, certKey, errors.New("improperly initialized order")
	}

	if key = o.account.ES256Key; key.id == "" {
		return b, certKey, errors.New("improperly initialized order")
	}

	ctx, cancel := context.WithCancel(ctx)

	defer cancel()

	if auth, err = c.fetchAuthz(ctx, o.Authorizations, key); err != nil {
		return b, certKey, err
	}

	defer func() {
		err = errors.Join(err, cleanup(ctx, cleanups))
	}()

	for _, az = range auth {
		if txt, fn, err = c.provisionAuthz(ctx, key, az, o.domains); err != nil {
			return b, certKey, err
		}

		records = append(records, txt)
		cleanups = append(cleanups, fn)
	}

	for _, txt := range records {
		waitForDns(ctx, txt.Name, txt.Txt, 5)
	}

	ch = make(chan error, len(auth))

	for _, az = range auth {
		go func(ctx context.Context, key ES256Key, az Authz) {
			ch <- c.validateAuthz(ctx, key, az)
		}(ctx, key, az)
	}

	for i = range auth {
		if err = errors.Join(err, <-ch); err != nil {
			// cancel pending challenges if there are any
			// and they have not already been cancelled
			if ctx.Err() == nil && i != len(auth)-1 {
				cancel()
			}
		}
	}

	if err != nil {
		return b, certKey, err
	}

	if err = c.pollForValidAuthz(ctx, o.Authorizations, key, 5); err != nil {
		return b, certKey, err
	}

	if err = c.pollForOrderReady(ctx, o.location, key, o, 5); err != nil {
		return b, certKey, err
	}

	if certKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		return b, nil, err
	}

	if err = c.finalize(ctx, o.Finalize, domains, key, certKey, o); err != nil {
		return b, nil, err
	}

	if url, err = c.pollForCertURL(ctx, o.location, key, o, 5); err != nil {
		return b, nil, err
	}

	b, err = c.downloadCert(ctx, url, key)

	return b, certKey, err
}

func (c *Client) downloadCert(ctx context.Context, url string, key ES256Key) ([]byte, error) {
	var (
		b   []byte
		err error
		res *http.Response
		bad Problem
		dec *jsontext.Decoder
	)

	if res, err = c.signedPostAsGet(ctx, url, key); err != nil {
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

func (c *Client) pollForValidAuthz(ctx context.Context, urls []string, key ES256Key, retries int) error {
	var (
		authz Authz
		err   error
		i     int
		n     = RetryError(retries)
	)

	for i < len(urls) {

		if err = c.fetchUnmarshalAuthz(ctx, urls[i], key, &authz); err != nil {
			return err
		}

		switch authz.Status {
		case AuthzStatusValid:
			i++
			continue
		case AuthzStatusPending:
			retries--
		case AuthzStatusInvalid:
			return ErrFailedAuthz
		default:
			return UnexpectedAuthzStatusError(authz.Status)
		}

		if retries--; retries <= 0 {
			return n
		}

		if err = pause(ctx, authz.retryAfter); err != nil {
			return err
		}

	}

	return nil

}

func (c *Client) pollForCertURL(ctx context.Context, url string, key ES256Key, out *Order, retries int) (string, error) {
	var (
		err error
		n   = RetryError(retries)
	)

	for err = c.fetchOrder(ctx, url, key, out); err == nil && retries > 0; err = c.fetchOrder(ctx, url, key, out) {
		if out.CertificateURL != "" {
			return out.CertificateURL, nil
		}

		if err = pause(ctx, out.retryAfter); err != nil {
			return "", err
		}

		retries--
	}

	if err != nil {
		return "", err
	}

	return "", n

}

func (c *Client) finalize(ctx context.Context, url string, domains []string, actKey ES256Key, certKey *ecdsa.PrivateKey, out *Order) error {
	var (
		err error
		csr csr
		b   []byte
		buf = new(bytes.Buffer)
		enc = jsontext.NewEncoder(buf)
	)

	if csr, err = newCSR(certKey, domains); err != nil {
		return err
	}

	if err = json.MarshalEncode(enc, &csr); err != nil {
		return err
	}

	b = buf.Bytes()

	if err = c.submitFinalize(ctx, url, actKey, b, out); err != nil {
		return err
	}

	return nil
}

func (c *Client) submitFinalize(ctx context.Context, url string, key ES256Key, b []byte, out *Order) error {
	var (
		res *http.Response
		err error
		dec *jsontext.Decoder
		bad Problem
	)

	if res, err = c.signedPost(ctx, url, key, b); err != nil {
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

	err = json.UnmarshalDecode(dec, out)
	if err != nil {
		return err
	}

	switch out.Status {
	case OrderStatusProcessing:
		// strictly speaking, this is the only valid response
	case OrderStatusInvalid:
		return ErrFailedOrder
	default:
		return UnexpectedOrderStatusError(out.Status)
	}

	out.retryAfter.parseRetryAfter(res)

	return nil
}

func (c *Client) pollForOrderReady(ctx context.Context, url string, key ES256Key, out *Order, retries int) error {
	var (
		err error
		n   = RetryError(retries)
	)

	for err = c.fetchOrder(ctx, url, key, out); err == nil && retries >= 0; err = c.fetchOrder(ctx, url, key, out) {
		switch out.Status {
		case OrderStatusPending:
			// keep polling
		case OrderStatusReady:
			return nil
		case OrderStatusInvalid:
			return ErrFailedOrder
		default:
			return UnexpectedOrderStatusError(out.Status)
		}

		if err = pause(ctx, out.retryAfter); err != nil {
			return err
		}

		retries--
	}

	if err != nil {
		return err
	}

	return n
}

func (c *Client) fetchOrder(ctx context.Context, url string, key ES256Key, out *Order) error {
	var (
		res *http.Response
		err error
		dec *jsontext.Decoder
		bad Problem
	)

	if res, err = c.signedPostAsGet(ctx, url, key); err != nil {
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

	err = json.UnmarshalDecode(dec, out)
	if err != nil {
		return err
	}

	out.retryAfter.parseRetryAfter(res)

	return nil

}
