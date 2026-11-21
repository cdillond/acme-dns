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
	"io"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"time"
)

type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type orderStatus uint32

const (
	orderStatusInvalid orderStatus = iota
	orderStatusPending
	orderStatusReady
	orderStatusProcessing
	orderStatusValid
	orderStatusUnknown
)

var orderStrings = [orderStatusUnknown]string{
	"invalid",
	"pending",
	"ready",
	"processing",
	"valid",
}

func newOrderStatus(s string) orderStatus {
	n := slices.Index(orderStrings[:], s)

	if n == -1 {
		return orderStatusUnknown
	}

	return orderStatus(n)
}

func (o orderStatus) String() string {
	if o >= orderStatusUnknown {
		return "unknown"
	}

	return orderStrings[o]
}

func (o *orderStatus) MarshalJSONTo(enc *jsontext.Encoder) error {
	return enc.WriteToken(jsontext.String(o.String()))
}

func (o *orderStatus) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	tok, err := dec.ReadToken()
	if err != nil {
		return err
	}
	if tok.Kind() != jsontext.KindString {
		return errors.New("invalid order status serialisation: " + tok.String())
	}

	s := tok.String()

	*o = newOrderStatus(s)

	return nil
}

type UnexpectedOrderStatusError orderStatus

func (u UnexpectedOrderStatusError) Error() string {
	return "unexpected order status: " + orderStatus(u).String()
}

// Optional configuration parameters for [Client.OrderCertificate]
type OrderCfg struct {
	// Optional: not supported by all CAs.
	NotBefore time.Time
	// Optional: not supported by all CAs.
	NotAfter time.Time
	// Optional: the default behavior uses [net.Resolver] with [net.Resolver.PreferGo] set to true.
	DnsConfirmation DNSConfirmationFunc
}

func identifiers(domains []string) []Identifier {
	out := make([]Identifier, 0, len(domains))

	for _, domain := range domains {
		out = append(out, Identifier{
			Type:  "dns",
			Value: domain,
		})
	}
	return out
}

type orderRequest struct {
	Identifiers []Identifier `json:"identifiers"`
	NotBefore   time.Time    `json:"notBefore,omitzero"`
	NotAfter    time.Time    `json:"notAfter,omitzero"`
}

type order struct {
	Status         orderStatus  `json:"status"`
	Expires        time.Time    `json:"expires"`
	Identifiers    []Identifier `json:"identifiers"`
	NotBefore      time.Time    `json:"notBefore"`
	NotAfter       time.Time    `json:"notAfter"`
	Authorizations []string     `json:"authorizations"`
	Finalize       string       `json:"finalize"`
	CertificateURL string       `json:"certificate"`
	Error          *Problem     `json:"error,omitzero"`

	location   string     `json:"-"`
	retryAfter retryAfter `json:"-"`
}

func filterChallenges(src []challenge) *challenge {
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

// When performing an ACME dns challenge (as part of [Client.OrderCertificate]), the [Client] confirms
// that all provisioned TXT records are publicly accessible before prompting the server to validate
// the challenge. By default, it does this by resolving each provisioned TXT record using the standard
// library's [net.Resolver], with [net.Resolver.PreferGo] set to true. On platforms where the Go resolver
// is not supported, and on builds where the Go resolver is explicitly disabled, the default behavior may
// run into timeouts caused by the platform's recursive resolver cache.
// To avoid this issue, users can supply a [DNSConfirmationFunc] that resolves the [TxtRecord] and returns
// true if the resolution succeeded. A potential implementation may choose to query a domain's authoritative
// name servers, rely on an external DNS server (such as 1.1.1.1), or (not recommended) skip confirmation
// entirely.
type DNSConfirmationFunc func(context.Context, TxtRecord) (bool, error)

func confirmTXT(ctx context.Context, record TxtRecord) (bool, error) {
	var (
		s   []string
		err error
	)

	if s, err = (&net.Resolver{PreferGo: true}).LookupTXT(ctx, record.Name); err != nil {
		return false, err
	}

	return slices.Contains(s, record.Value), nil
}

func pollForDNS(ctx context.Context, record TxtRecord, fn DNSConfirmationFunc, retries int) error {
	var (
		err       error
		dnsErr    *net.DNSError
		ok, found bool
		n         = RetryError(retries)
		log, _    = ctx.Value(LogKey{}).(*slog.Logger)
	)

	if log != nil {
		log = log.With("record", record)
		log.Info("querying dns")
	}

	if fn == nil {
		fn = confirmTXT
	}

	for ; retries >= 0; retries-- {
		if found, err = fn(ctx, record); err != nil {
			if dnsErr, ok = errors.AsType[*net.DNSError](err); ok {
				switch {
				case dnsErr.IsNotFound, dnsErr.IsTemporary:
				default:
					return err
				}
			} else {
				return err
			}
		}

		if found {
			return nil
		}

		if retries > 0 {
			select {
			case <-time.After(DefaultInterval):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}

	return n
}

func (c *Client) provisionAuthz(ctx context.Context, key es256Key, az authz, domains map[string]Provider) (TxtRecord, CleanupFunc, error) {
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
		TTL:   DefaultTTL,
		Name:  "_acme-challenge." + az.Identifier.Value,
		Value: newDNS01Txt(dnsChallenge.Token, key),
	}

	cleanup, err := p.Provision(withLogger(ctx, c.Log), txt)
	if err != nil {
		return TxtRecord{}, nil, err
	}
	if cleanup == nil {
		cleanup = defaultCleanupFn
	}

	return txt, cleanup, nil
}

func (c *Client) validateAuthz(ctx context.Context, id string, key es256Key, az authz) error {
	var (
		dns *challenge
		raw rawChallenge
		err error
	)

	dns = filterChallenges(az.Challenges)
	if dns == nil {
		return errors.New("no dns challenge available for Authz")
	}

	raw, err = c.acceptChallenge(ctx, dns.URL, id, key)

	for err == nil {
		switch raw.Status {
		case challengeStatusProcessing:
			// keep polling; no retry limit
		case challengeStatusValid:
			return nil
		case challengeStatusInvalid:
			return ErrFailedChallenge
		default:
			return UnexpectedChallengeStatusError(raw.Status)
		}

		if err = pause(ctx, raw.retryAfter); err != nil {
			return err
		}

		raw, err = c.fetchRawChallenge(ctx, dns.URL, id, key)
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

type AttemptCfg struct {
	DnsConfirmation DNSConfirmationFunc
}

func (c Client) attempt(ctx context.Context, o *order, id string, key es256Key, domains []string, providers map[string]Provider, cfg OrderCfg) (b []byte, certKey *ecdsa.PrivateKey, err error) {
	var (
		ch       chan error
		az       authz
		auths    []authz
		url      string
		txt      TxtRecord
		fn       CleanupFunc
		records  []TxtRecord
		cleanups []CleanupFunc
		i        int
	)

	ctx, cancel := context.WithCancel(ctx)

	defer cancel()

	if auths, err = c.fetchAuthz(ctx, o.Authorizations, id, key); err != nil {
		return b, certKey, err
	}

	defer func() {
		err = errors.Join(err, cleanup(withLogger(ctx, c.Log), cleanups))
	}()

	for _, az = range auths {
		if txt, fn, err = c.provisionAuthz(ctx, key, az, providers); err != nil {
			return b, certKey, err
		}

		records = append(records, txt)
		cleanups = append(cleanups, fn)
	}

	for _, txt = range records {
		if err = pollForDNS(ctx, txt, cfg.DnsConfirmation, 5); err != nil {
			return b, certKey, err
		}
	}

	ch = make(chan error, len(auths))

	for _, az = range auths {
		go func(ctx context.Context, key es256Key, az authz) {
			ch <- c.validateAuthz(ctx, id, key, az)
		}(ctx, key, az)
	}

	for i = range auths {
		if err = errors.Join(err, <-ch); err != nil {
			// cancel pending challenges if there are any
			// and they have not already been cancelled
			if ctx.Err() == nil && i != len(auths)-1 {
				cancel()
			}
		}
	}

	if err != nil {
		return b, certKey, err
	}

	if err = c.pollForValidAuthz(ctx, o.Authorizations, id, key, 5); err != nil {
		return b, certKey, err
	}

	if err = c.pollForOrderReady(ctx, o.location, id, key, o, 5); err != nil {
		return b, certKey, err
	}

	if certKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		return b, nil, err
	}

	if err = c.finalize(ctx, o.Finalize, id, domains, key, certKey, o); err != nil {
		return b, nil, err
	}

	if url, err = c.pollForCertURL(ctx, o.location, id, key, o, 5); err != nil {
		return b, nil, err
	}

	b, err = c.downloadCert(ctx, url, id, key)

	return b, certKey, err
}

func (c *Client) downloadCert(ctx context.Context, url, id string, key es256Key) ([]byte, error) {
	var (
		b   []byte
		err error
		res *http.Response
		bad Problem
		dec *jsontext.Decoder
	)

	if res, err = c.signedPostID(ctx, url, id, key, postAsGetPayload); err != nil {
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

func (c *Client) pollForValidAuthz(ctx context.Context, urls []string, id string, key es256Key, retries int) error {
	var (
		authz authz
		err   error
		i     int
		n     = RetryError(retries)
	)

	for i < len(urls) {

		if err = c.fetchUnmarshalAuthz(ctx, urls[i], id, key, &authz); err != nil {
			return err
		}

		switch authz.Status {
		case authzStatusValid:
			i++
			continue
		case authzStatusPending:
			retries--
		case authzStatusInvalid:
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

func (c *Client) pollForCertURL(ctx context.Context, url, id string, key es256Key, out *order, retries int) (string, error) {
	var (
		err error
		n   = RetryError(retries)
	)

	for err = c.fetchOrder(ctx, url, id, key, out); err == nil && retries > 0; err = c.fetchOrder(ctx, url, id, key, out) {
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

func (c *Client) finalize(ctx context.Context, url, id string, domains []string, actKey es256Key, certKey *ecdsa.PrivateKey, out *order) error {
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

	if err = c.submitFinalize(ctx, url, id, actKey, b, out); err != nil {
		return err
	}

	return nil
}

func (c *Client) submitFinalize(ctx context.Context, url, id string, key es256Key, b []byte, out *order) error {
	var (
		res *http.Response
		err error
		dec *jsontext.Decoder
		bad Problem
	)

	if res, err = c.signedPostID(ctx, url, id, key, b); err != nil {
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
	case orderStatusProcessing:
		// strictly speaking, OrderStatusProcessing is the only valid response
	case orderStatusInvalid:
		return ErrFailedOrder
	default:
		return UnexpectedOrderStatusError(out.Status)
	}

	out.retryAfter.parse(res)

	return nil
}

func (c *Client) pollForOrderReady(ctx context.Context, url, id string, key es256Key, out *order, retries int) error {
	var (
		err error
		n   = RetryError(retries)
	)

	for err = c.fetchOrder(ctx, url, id, key, out); err == nil && retries >= 0; err = c.fetchOrder(ctx, url, id, key, out) {
		switch out.Status {
		case orderStatusPending:
			// keep polling
		case orderStatusReady:
			return nil
		case orderStatusInvalid:
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

func (c *Client) fetchOrder(ctx context.Context, url, id string, key es256Key, out *order) error {
	var (
		res *http.Response
		err error
		dec *jsontext.Decoder
		bad Problem
	)

	if res, err = c.signedPostID(ctx, url, id, key, postAsGetPayload); err != nil {
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

	out.retryAfter.parse(res)

	return nil

}
