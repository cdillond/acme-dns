package acme

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

/*
	once an account exists, the order of operations goes:
	1. submit and order request
	2. for each authorisation required by that request:
		a) fetch the authorisation
		b) fetch the appropriate DNS challenge info
		c) update the dns provider
		d) poll the challenge until the status is valid
		e) poll the authorisation until the status is valid (this and the prior step are redundant, probably)
	3. poll the order until it reflects a status of valid
	4. submit a CSR request to the finalise endpoint
	5. request the certificate from the certificate URL of the finalised order
*/

const (
	joseMIME  = "application/jose+json"
	UserAgent = "go.ciaran.lol/acme-dns"
)

type Client struct {
	CADirURL CADirURL
	dir      acmeDirectory
	nonce    string
}

func (c Client) RequestNonce(ctx context.Context) (string, error) {
	var (
		s   string
		err error
		req *http.Request
		res *http.Response
	)

	if req, err = http.NewRequest(http.MethodHead, c.dir.NewNonce, nil); err != nil {
		return s, err
	}

	if res, err = http.DefaultClient.Do(req); err != nil {
		return s, err
	}

	s = res.Header.Get("Replay-Nonce")
	if s == "" {
		err = errors.New("no nonce provided")
	}

	return s, err
}

type nonceSource struct {
	ctx    context.Context
	client *Client
}

func (n nonceSource) Nonce() (string, error) {
	return n.client.RequestNonce(n.ctx)
}

func (c Client) jws(ctx context.Context, key ES256Key, url, kid string, payload []byte) (string, error) {
	embedJWK := kid == ""

	opts := jose.SignerOptions{
		NonceSource: nonceSource{
			ctx:    ctx,
			client: &c,
		},
		EmbedJWK: embedJWK,
		ExtraHeaders: map[jose.HeaderKey]any{
			"url": url,
		}}

	// go-jose embeds the public key when EmbedJWK is true and otherwise emits
	// KeyID as the "kid" header, matching ACME's jwk/kid mutual exclusion
	// (RFC 8555 section 6.2). KeyID is ignored while EmbedJWK is true.
	jwk := jose.JSONWebKey{
		Key:   key.pk,
		KeyID: kid,
	}

	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       jwk,
	}, &opts,
	)

	if err != nil {
		return "", err
	}

	raw, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}

	return raw.FullSerialize(), nil
}

func (c Client) signedPost(ctx context.Context, url, kid string, key ES256Key, payload []byte) (*http.Response, error) {
	var (
		req *http.Request
		res *http.Response
		err error
		jws string
	)

	if jws, err = c.jws(ctx, key, url, kid, payload); err != nil {
		return res, err
	}

	if req, err = http.NewRequest(http.MethodPost, url, strings.NewReader(jws)); err != nil {
		return res, err
	}

	req.Header.Set("Content-Type", joseMIME)
	req.Header.Set("User-Agent", UserAgent)

	return http.DefaultClient.Do(req)
}

func (c Client) signedPostAsGet(ctx context.Context, url, kid string, key ES256Key) (*http.Response, error) {
	return c.signedPost(ctx, url, kid, key, []byte{})
}

// RequestAccount requests a new or existing account from the ACME server. If the information
// provided in the [AccountRequest] argument matches an existing account, the server will return
// the existing account and will otherwise create a new account, unless [AccountRequest.OnlyReturnExisting] is
// set to [true], in which case it will only return existing accounts and return an [error] instead
// of creating a new account. The old return value indicates whether or not the account already
// existed. If old is [false], then the account was newly created, and vice-versa.
//
// Note: The CA server is free to ignore data in the [AccountRequest.Contact], [AccountRequest.TermsOfServiceAgreed],
// and [AccountRequest.ExternalAccountBinding] fields, and the corresponding values in the returned Account object might
// not reflect the actual values stored by the CA.
func (c Client) RequestAccount(ctx context.Context, a AccountRequest) (acc Account, old bool, err error) {
	var (
		raw []byte
		dto accountResponse
		res *http.Response
		dec *jsontext.Decoder
	)

	if raw, err = json.Marshal(a); err != nil {
		return acc, false, err
	}

	if res, err = c.signedPost(ctx, c.dir.NewAccount, "", a.ES256Key, raw); err != nil {
		return acc, false, err
	}

	defer func() {
		err = errors.Join(err, res.Body.Close())
	}()

	dec = jsontext.NewDecoder(res.Body)

	if err = json.UnmarshalDecode(dec, &dto); err != nil {
		return acc, false, err
	}

	acc, err = newAccount(a, dto, res.Header.Get("Location"))

	return acc, res.StatusCode == http.StatusOK, err
}

func (c Client) NewOrder(ctx context.Context, account Account, order OrderRequest) (Order, error) {
	var (
		out Order
		bad Problem
		err error
		raw []byte
		res *http.Response
		dec *jsontext.Decoder
	)

	if account.Location == "" {
		return out, errors.New("account location must not be empty")
	}

	if len(order.Domains) == 0 {
		return out, errors.New("order domains must not be empty")
	}

	if raw, err = json.Marshal(order.toDto()); err != nil {
		return out, err
	}

	if res, err = c.signedPost(ctx, c.dir.NewOrder, account.Location, account.ES256Key, raw); err != nil {
		return out, err
	}

	defer func() {
		err = errors.Join(err, res.Body.Close())
	}()

	dec = jsontext.NewDecoder(res.Body)

	if res.StatusCode != http.StatusCreated {
		if err = json.UnmarshalDecode(dec, &bad); err != nil {
			return out, err
		}
		err = &bad
		return out, err
	}

	if err = json.UnmarshalDecode(dec, &out); err != nil {
		return out, err
	}

	// The order URL is not in the body; it comes from the Location header.
	out.Location = res.Header.Get("Location")
	// pass on the original domains map from the request
	out.domains = order.Domains

	return out, err
}

func (c Client) fetchUnmarshalAuthz(ctx context.Context, url, loc string, key ES256Key, out *Authz) error {
	var (
		err error
		res *http.Response
		dec *jsontext.Decoder
		bad Problem
	)

	res, err = c.signedPostAsGet(ctx, url, loc, key)
	if err != nil {
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
	} else {
		err = json.UnmarshalDecode(dec, out)
	}

	return err
}

func parseRetryAfterHeader(s string) time.Time {
	var (
		t   time.Time
		n   int64
		err error
	)
	if s == "" {
		return t
	}
	// implemented either as a non-negative number of seconds OR a date time
	if n, err = strconv.ParseInt(s, 10, 64); err != nil {
		if n < 0 {
			return t
		}
		return time.Now().Add(time.Duration(n) * time.Second)
	}

	t, _ = time.Parse(http.TimeFormat, s)

	return t
}

func (c Client) FetchRawChallenge(ctx context.Context, url string, a Account) (RawChallenge, error) {
	var (
		out RawChallenge
		res *http.Response
		dec *jsontext.Decoder
		bad Problem
		err error
	)

	if res, err = c.signedPostAsGet(ctx, url, a.Location, a.ES256Key); err != nil {
		return out, err
	}

	defer func() {
		err = errors.Join(err, res.Body.Close())
	}()

	dec = jsontext.NewDecoder(res.Body)

	if res.StatusCode != http.StatusOK {
		err = json.UnmarshalDecode(dec, &bad)
		if err != nil {
			return out, err
		}
		err = &bad
	} else {
		err = json.UnmarshalDecode(dec, &out)
		if err != nil {
			out.RetryAfter = parseRetryAfterHeader(
				res.Header.Get("Retry-After"),
			)
		}
	}

	return out, err
}

func (c Client) FetchAuthz(ctx context.Context, a Account, o Order) ([]Authz, error) {
	var (
		out = make([]Authz, len(o.Authorizations))
		err error
		i   int
		url string
	)

	for i, url = range o.Authorizations {
		if err = c.fetchUnmarshalAuthz(ctx, url, a.Location, a.ES256Key, &out[i]); err != nil {
			return nil, err
		}
	}

	return out, nil
}

func NewClient(ctx context.Context, CADirURL CADirURL) (Client, error) {
	var (
		c   Client
		err error
		req *http.Request
		res *http.Response
		dec *jsontext.Decoder
	)

	if req, err = http.NewRequest(http.MethodGet, string(CADirURL), nil); err != nil {
		return c, err
	}

	if res, err = http.DefaultClient.Do(req.WithContext(ctx)); err != nil {
		return c, err
	}

	defer func() {
		err = errors.Join(err, res.Body.Close())
	}()

	dec = jsontext.NewDecoder(res.Body)

	if err = json.UnmarshalDecode(dec, &c.dir); err != nil {
		return c, err
	}

	c.CADirURL = CADirURL

	return c, nil
}
