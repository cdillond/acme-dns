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

// Optional configuration parameters for [Client.OrderCertificate].
type OrderCfg struct {
	// Optional: not supported by all CAs.
	NotBefore time.Time
	// Optional: not supported by all CAs.
	NotAfter time.Time
	// Optional: the TTL for provisioned DNS TXT records. Defaults to 60 if it is 0.
	RecordTTLSeconds uint16
	// Optional: the resolver used when confirming that provisioned DNS records have propagated.
	// If nil, it defaults to the standard library's PreferGo resolver.
	Resolver *net.Resolver
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

func (c *Client) provisionAuthz(ctx context.Context, key es256Key, az authz, domains map[string]Provider, ttl uint16) (TXTRecord, CleanupFunc, error) {
	dnsChallenge := filterChallenges(az.Challenges)
	if dnsChallenge == nil {
		return TXTRecord{}, nil, errors.New("no dns challenge available for Authz")
	}

	n := az.Identifier.Value
	if az.Wildcard {
		n = "*." + n
	}

	p := domains[n]
	if p == nil {
		return TXTRecord{}, nil, errors.New("could not find registered provider")
	}

	txt := TXTRecord{
		TTL:   ttl,
		Name:  "_acme-challenge." + az.Identifier.Value,
		Value: newDNS01Txt(dnsChallenge.Token, key),
	}

	cleanup, err := p.Provision(withLogger(ctx, c.Log), txt)
	if err != nil {
		return TXTRecord{}, nil, err
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

	defer func() {
		if err != nil {
			err = errors.Join(err, fmt.Errorf("unable to validate authz: %v", az))
		}
	}()

	dns = filterChallenges(az.Challenges)
	if dns == nil {
		err = errors.New("no dns challenge available for Authz")
		return err
	}

	raw, err = c.acceptChallenge(ctx, dns.URL, id, key)

	for err == nil {
		switch raw.Status {
		case challengeStatusPending, challengeStatusProcessing:
			if c.Log != nil {
				c.Log.Info("waiting for server challenge update", "challenge", raw)
			}
			// keep polling; no retry limit
		case challengeStatusValid:
			return nil
		case challengeStatusInvalid:
			err = errors.Join(ErrFailedChallenge, fmt.Errorf("challenge %q invalid", dns.URL), raw.Error)
			return err
		default:
			err = UnexpectedChallengeStatusError(raw.Status)
			return err
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

	return err
}

func (c Client) attempt(ctx context.Context, o *order, id string, key es256Key, domains []string, providers map[string]Provider, cfg OrderCfg) (b []byte, certKey *ecdsa.PrivateKey, err error) {
	var (
		ch                            chan error
		az                            authz
		auths, pendingAuths, badAuths []authz
		url                           string
		txt                           TXTRecord
		fn                            CleanupFunc
		records                       []TXTRecord
		cleanups                      []CleanupFunc
		i                             int
	)

	ctx, cancel := context.WithCancel(ctx)

	defer cancel()

	if auths, err = c.fetchAuthz(ctx, o.Authorizations, id, key); err != nil {
		return b, certKey, err
	}

	if len(auths) == 0 {
		return b, certKey, errors.New("no authorizations returned by the server")
	}

	pendingAuths, _, badAuths = partitionAuthz(auths)

	if len(badAuths) > 0 {
		err = ErrFailedAuthz
		for _, az = range badAuths {
			err = errors.Join(err, fmt.Errorf("authorization %q has status %s", az.Identifier.Value, az.Status))
		}
		return b, certKey, err
	}

	defer func() {
		err = errors.Join(err, cleanup(withLogger(ctx, c.Log), cleanups))
	}()

	for _, az = range pendingAuths {
		if txt, fn, err = c.provisionAuthz(ctx, key, az, providers, cfg.RecordTTLSeconds); err != nil {
			err = errors.Join(err, fmt.Errorf("unable to provision authz: %v", az))
			return b, certKey, err
		}

		records = append(records, txt)
		cleanups = append(cleanups, fn)
	}

	for _, txt = range records {
		if err = pollForDNS(ctx, c.Log, cfg.Resolver, txt, c.PollInterval); err != nil {
			err = errors.Join(fmt.Errorf("unable to confirm dns record: %v", txt), err)
			return b, certKey, err
		}
	}

	ch = make(chan error, len(pendingAuths))

	for _, az = range pendingAuths {
		go func(ctx context.Context, key es256Key, az authz) {
			ch <- c.validateAuthz(ctx, id, key, az)
		}(ctx, key, az)
	}

	for i = range pendingAuths {
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

	if err = c.pollForValidAuthz(ctx, o.Authorizations, id, key); err != nil {
		err = errors.Join(err, errors.New("failed to confirm authz validity"))
		return b, certKey, err
	}

	if err = c.pollForOrderReady(ctx, o.location, id, key, o); err != nil {
		err = errors.Join(err, errors.New("failed to confirm order readiness"))
		return b, certKey, err
	}

	if certKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		err = errors.Join(err, errors.New("failed to generate certificate private key"))
		return b, nil, err
	}

	if err = c.finalize(ctx, o.Finalize, id, domains, key, certKey, o); err != nil {
		err = errors.Join(err, errors.New("failed to finalize order"))
		return b, nil, err
	}

	if url, err = c.pollForCertURL(ctx, o.location, id, key, o); err != nil {
		err = errors.Join(err, errors.New("failed to obtain certificate URL"))
		return b, nil, err
	}

	b, err = c.downloadCert(ctx, url, id, key)
	if err != nil {
		err = errors.Join(err, errors.New("failed to download certificate"))
	}

	return b, certKey, err
}

func (c *Client) downloadCert(ctx context.Context, url, id string, key es256Key) ([]byte, error) {
	var (
		b   []byte
		err error
		res *http.Response
	)

	if res, err = c.signedPostID(ctx, url, id, key, postAsGetPayload); err != nil {
		return b, err
	}

	defer func() {
		err = errors.Join(err, res.Body.Close())
	}()

	if res.StatusCode != http.StatusOK {
		err = errors.New("server responded with an unexpected status: " + res.Status)
		return b, err
	}

	b, err = io.ReadAll(res.Body)

	return b, err

}

func (c *Client) pollForValidAuthz(ctx context.Context, urls []string, id string, key es256Key) error {
	var (
		authz authz
		err   error
		i     int
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
		case authzStatusInvalid, authzStatusDeactivated, authzStatusExpired, authzStatusRevoked:
			return errors.Join(ErrFailedAuthz, fmt.Errorf("authorization %q has status %s", authz.Identifier.Value, authz.Status))
		default:
			return UnexpectedAuthzStatusError(authz.Status)
		}

		if err = pause(ctx, authz.retryAfter); err != nil {
			return err
		}

	}

	return nil

}

func (c *Client) pollForCertURL(ctx context.Context, url, id string, key es256Key, out *order) (string, error) {
	var err error

	if out.CertificateURL != "" {
		return out.CertificateURL, nil
	}

	// section 7.4 of the rfc requires the client to respect the retry-after header of the response to an
	// order finalization request before polling for the certificate url.
	if err = pause(ctx, out.retryAfter); err != nil {
		return "", err
	}

	for err = c.fetchOrder(ctx, url, id, key, out); err == nil; err = c.fetchOrder(ctx, url, id, key, out) {
		switch out.Status {
		case orderStatusInvalid:
			return "", ErrFailedOrder
		case orderStatusProcessing, orderStatusValid:
			// at this point the order should have progressed past "pending" and "ready"
		default:
			return "", UnexpectedOrderStatusError(out.Status)
		}

		if out.CertificateURL != "" {
			return out.CertificateURL, nil
		}

		if err = pause(ctx, out.retryAfter); err != nil {
			return "", err
		}
	}

	return "", err
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
		res   *http.Response
		err   error
		dec   *jsontext.Decoder
		after string
	)

	if res, err = c.signedPostID(ctx, url, id, key, b); err != nil {
		return err
	}

	defer func() {
		err = errors.Join(err, res.Body.Close())
	}()

	if res.StatusCode != http.StatusOK {
		err = errors.New("server responded with an unexpected status: " + res.Status)
		return err
	}

	dec = jsontext.NewDecoder(res.Body)
	if err = json.UnmarshalDecode(dec, out); err != nil {
		return err
	}

	switch out.Status {
	case orderStatusProcessing:
		// rfc8555 section 7.4 requires the client to inspect the retry-after header and wait at least that
		// long when the order is still processing; however, our retryAfter.parse() method falls back to adding
		// an interval to the current time which we don't want. if there is no retry-after header, we can proceed
		// to poll for the certificate url immediately.
		after = res.Header.Get("Retry-After")
		if after == "" {
			out.retryAfter = retryAfter{}
		} else {
			out.retryAfter = retryAfter(parseRetryAfterHeader(after))
		}
	case orderStatusValid:
		// we can proceed directly without worrying about the retry-after header
		out.retryAfter = retryAfter{}
	case orderStatusInvalid:
		return ErrFailedOrder
	default:
		return UnexpectedOrderStatusError(out.Status)
	}

	return nil
}

func (c *Client) pollForOrderReady(ctx context.Context, url, id string, key es256Key, out *order) error {
	var err error

	for err = c.fetchOrder(ctx, url, id, key, out); err == nil; err = c.fetchOrder(ctx, url, id, key, out) {
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
	}

	return err
}

func (c *Client) fetchOrder(ctx context.Context, url, id string, key es256Key, out *order) error {
	var (
		res *http.Response
		err error
		dec *jsontext.Decoder
	)

	if res, err = c.signedPostID(ctx, url, id, key, postAsGetPayload); err != nil {
		return err
	}

	defer func() {
		err = errors.Join(err, res.Body.Close())
	}()

	if res.StatusCode != http.StatusOK {
		err = errors.New("server responded with an unexpected status: " + res.Status)
		return err
	}

	dec = jsontext.NewDecoder(res.Body)
	if err = json.UnmarshalDecode(dec, out); err != nil {
		return err
	}

	out.retryAfter.parse(res, c.PollInterval)

	return nil

}
