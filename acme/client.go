package acme

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"net/http"
	"strings"
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

func (c Client) requestNonce(ctx context.Context) (string, error) {
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

func (c Client) jws(ctx context.Context, url string, key ES256Key, payload []byte) (string, error) {
	var (
		nonce string
		err   error
		dto   jwsDto
		buf   = new(bytes.Buffer)
		enc   = jsontext.NewEncoder(buf)
	)

	if nonce, err = c.requestNonce(ctx); err != nil {
		return "", err
	}

	if dto, err = sign(url, key, payload, nonce); err != nil {
		return "", err
	}

	if err = json.MarshalEncode(enc, dto); err != nil {
		return "", err
	}

	return buf.String(), nil
}

func (c Client) signedPost(ctx context.Context, url string, key ES256Key, payload []byte) (*http.Response, error) {
	var (
		req *http.Request
		res *http.Response
		err error
		jws string
	)

	if jws, err = c.jws(ctx, url, key, payload); err != nil {
		return res, err
	}

	if req, err = http.NewRequest(http.MethodPost, url, strings.NewReader(jws)); err != nil {
		return res, err
	}

	req.Header.Set("Content-Type", joseMIME)
	req.Header.Set("User-Agent", UserAgent)

	return http.DefaultClient.Do(req)
}

func (c Client) signedPostAsGet(ctx context.Context, url string, key ES256Key) (*http.Response, error) {
	return c.signedPost(ctx, url, key, []byte{})
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

	if res, err = c.signedPost(ctx, c.dir.NewAccount, a.ES256Key, raw); err != nil {
		return acc, false, err
	}

	defer func() {
		err = errors.Join(err, res.Body.Close())
	}()

	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusCreated {
		return acc, false, errors.New("server responded with an unexpected status: " + res.Status)
	}

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

	if account.ES256Key.id == "" {
		return out, errors.New("uninitialized account key")
	}

	if len(order.Domains) == 0 {
		return out, errors.New("order domains must not be empty")
	}

	if raw, err = json.Marshal(order.toDto()); err != nil {
		return out, err
	}

	if res, err = c.signedPost(ctx, c.dir.NewOrder, account.ES256Key, raw); err != nil {
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

	out.location = res.Header.Get("Location")
	out.domains = order.Domains
	out.account = &account
	out.client = &c

	return out, err
}

func (c Client) fetchUnmarshalAuthz(ctx context.Context, url string, key ES256Key, out *Authz) error {
	var (
		err error
		res *http.Response
		dec *jsontext.Decoder
		bad Problem
	)

	res, err = c.signedPostAsGet(ctx, url, key)
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
		out.retryAfter.parseRetryAfter(res)
	}

	return err
}

func (c Client) fetchChallenge(ctx context.Context, url string, key ES256Key, payload []byte) (RawChallenge, error) {
	var (
		out RawChallenge
		res *http.Response
		dec *jsontext.Decoder
		bad Problem
		err error
	)

	if res, err = c.signedPost(ctx, url, key, payload); err != nil {
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
		if err == nil {
			out.retryAfter.parseRetryAfter(res)
		}
	}

	return out, err
}

// fetchRawChallenge fetches the current state of a challenge without starting
// validation.
func (c Client) fetchRawChallenge(ctx context.Context, url string, key ES256Key) (RawChallenge, error) {
	return c.fetchChallenge(ctx, url, key, []byte{})
}

// acceptChallenge tells the ACME server that the challenge response has been
// provisioned and that validation should begin. Per RFC 8555 section 7.5.1,
// this is a POST with an empty JSON object ("{}") to the challenge URL.
func (c Client) acceptChallenge(ctx context.Context, url string, key ES256Key) (RawChallenge, error) {
	return c.fetchChallenge(ctx, url, key, []byte("{}"))
}

func (c Client) fetchAuthz(ctx context.Context, urls []string, key ES256Key) ([]Authz, error) {
	var (
		err error
		i   int
		url string
		out = make([]Authz, len(urls))
	)

	for i, url = range urls {
		if err = c.fetchUnmarshalAuthz(ctx, url, key, &out[i]); err != nil {
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

	if res.StatusCode != http.StatusOK {
		return c, errors.New("server responded with an unexpected status: " + res.Status)
	}

	if err = json.UnmarshalDecode(dec, &c.dir); err != nil {
		return c, err
	}

	c.CADirURL = CADirURL

	return c, nil
}
