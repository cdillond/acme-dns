package acme

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"log/slog"
	"maps"
	"net/http"
	"slices"
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

var postAsGetPayload = []byte{}

type Client struct {
	Dir ACMEDirectory
	Log *slog.Logger
}

func (c Client) requestNonce(ctx context.Context) (string, error) {
	var (
		s   string
		err error
		req *http.Request
		res *http.Response
	)

	if req, err = http.NewRequest(http.MethodHead, c.Dir.NewNonce, nil); err != nil {
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

func (c Client) signedPostID(ctx context.Context, url, id string, key es256Key, payload []byte) (*http.Response, error) {
	var (
		req   *http.Request
		res   *http.Response
		err   error
		h     jwsHeaderWithKID
		jws   []byte
		nonce string
	)

	if nonce, err = c.requestNonce(ctx); err != nil {
		return nil, err
	}

	h = key.newJWSHeaderWithKID(url, id, nonce)

	if jws, err = jwsBytes(key, h, payload); err != nil {
		return nil, err
	}

	if req, err = http.NewRequest(http.MethodPost, url, bytes.NewReader(jws)); err != nil {
		return res, err
	}

	req.Header.Set("Content-Type", joseMIME)
	req.Header.Set("User-Agent", UserAgent)

	return http.DefaultClient.Do(req)
}

func (c Client) signedPostJWK(ctx context.Context, url string, key es256Key, payload []byte) (*http.Response, error) {
	var (
		req   *http.Request
		res   *http.Response
		err   error
		h     jwsHeaderWithJWK
		jws   []byte
		nonce string
	)

	if nonce, err = c.requestNonce(ctx); err != nil {
		return nil, err
	}

	if h, err = key.newJWSHeaderWithJWK(url, nonce); err != nil {
		return nil, err
	}

	if jws, err = jwsBytes(key, h, payload); err != nil {
		return nil, err
	}

	if req, err = http.NewRequest(http.MethodPost, url, bytes.NewReader(jws)); err != nil {
		return res, err
	}

	req.Header.Set("Content-Type", joseMIME)
	req.Header.Set("User-Agent", UserAgent)

	return http.DefaultClient.Do(req)
}

// RequestAccount requests a new or existing [Account] from the ACME server. If the provided [AccountKey]
// matches an existing account, the server will return
// the existing account and will otherwise create a new account, unless [AccountCfg.OnlyReturnExisting] is
// set to true, in which case it will only return existing accounts and return an error instead
// of creating a new account.
//
// Note: The ACME server is free to ignore data in the [AccountCfg.Contact] and [AccountCfg.TermsOfServiceAgreed],
// fields, and the corresponding values in the returned [AccountData] object might
// not reflect the actual values stored by the CA. Additionally, the [AccountData.CreatedAt] at field is non-standard
// and may not be provided by the server; other non-standard response fields are discarded.
func (c Client) RequestAccount(ctx context.Context, key AccountKey, cfg AccountCfg) (acc Account, data AccountData, err error) {
	var (
		raw []byte
		res *http.Response
		dec *jsontext.Decoder
		bad Problem
		loc string
	)

	if c.Dir.Meta.ExternalAccountRequired {
		return acc, data, errors.New("external account binding is required by the ACME server")
	}

	if raw, err = json.Marshal(cfg); err != nil {
		return acc, data, err
	}

	if res, err = c.signedPostJWK(ctx, c.Dir.NewAccount, key.es256Key, raw); err != nil {
		return acc, data, err
	}

	defer func() {
		err = errors.Join(err, res.Body.Close())
	}()

	dec = jsontext.NewDecoder(res.Body)

	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusCreated {
		if err = json.UnmarshalDecode(dec, &bad); err != nil {
			return acc, data, errors.Join(err, errors.New("server responded with an unexpected status: "+res.Status))
		}
		return acc, data, &bad
	}

	if loc = res.Header.Get("Location"); loc == "" {
		return acc, data, errors.New("no account ID provided by the server")
	}

	if err = json.UnmarshalDecode(dec, &data); err != nil {
		return acc, data, err
	}

	acc.ID = loc
	acc.Key = key

	return acc, data, err
}

// RequestAccountWithEAB requests an account with external account binding. This feature is not supported by most public/free
// CAs, including Let's Encrypt.
func (c Client) RequestAccountWithEAB(ctx context.Context, key AccountKey, eab EABRequest, cfg AccountCfg) (acc Account, data AccountData, err error) {
	var (
		eabJWS   jwsDto
		jwk      jwk
		jwkBytes []byte
		payload  []byte
		res      *http.Response
		dec      *jsontext.Decoder
		loc      string
		bad      Problem
	)

	if !c.Dir.Meta.ExternalAccountRequired {
		return acc, data, errors.New("external account binding not supported by this ACME server")
	}
	if eab.KID == "" {
		return acc, data, errors.New("EABRequest KID field is required")
	}
	if eab.Alg == "" {
		return acc, data, errors.New("EABRequest Alg field is required")
	}

	// step 1: calculate the jwk for the account key; this will be used both in the EAB and in the JWS

	if jwk, err = key.newJWK(); err != nil {
		return acc, data, err
	}

	if jwkBytes, err = json.Marshal(&jwk, json.Deterministic(true)); err != nil {
		return acc, data, err
	}

	if eabJWS, err = signMAC(c.Dir.NewAccount, eab.KID, eab.Alg, eab.Hash, jwkBytes); err != nil {
		return acc, data, err
	}

	if payload, err = json.Marshal(&struct {
		Eab jwsDto `json:"externalAccountBinding"`
		AccountCfg
	}{
		Eab:        eabJWS,
		AccountCfg: cfg,
	}); err != nil {
		return acc, data, err
	}

	if res, err = c.signedPostJWK(ctx, c.Dir.NewAccount, key.es256Key, payload); err != nil {
		return acc, data, err
	}

	defer func() {
		err = errors.Join(err, res.Body.Close())
	}()

	dec = jsontext.NewDecoder(res.Body)

	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusCreated {
		if err = json.UnmarshalDecode(dec, &bad); err != nil {
			return acc, data, errors.Join(err, errors.New("server responded with an unexpected status: "+res.Status))
		}
		return acc, data, &bad
	}

	if loc = res.Header.Get("Location"); loc == "" {
		return acc, data, errors.New("no account ID provided by the server")
	}

	if err = json.UnmarshalDecode(dec, &data); err != nil {
		return acc, data, err
	}

	acc.ID = loc
	acc.Key = key

	return acc, data, err
}

// DeactivateAccount deactivates an account. If it succeeds, all pending and future requests authorized by the
// account key will return an unauthorized response.
func (c Client) DeactivateAccount(ctx context.Context, account Account) (AccountData, error) {
	var (
		err  error
		b    []byte
		bad  Problem
		dec  *jsontext.Decoder
		res  *http.Response
		data AccountData
	)

	if b, err = json.Marshal(&struct {
		Status AccountStatus `json:"status"`
	}{
		Status: AccountStatusDeactivated,
	}); err != nil {
		return data, err
	}

	if res, err = c.signedPostID(ctx, account.ID, account.ID, account.Key.es256Key, b); err != nil {
		return data, err
	}

	defer func() {
		err = errors.Join(err, res.Body.Close())
	}()

	dec = jsontext.NewDecoder(res.Body)

	if res.StatusCode != http.StatusOK {
		if err = json.UnmarshalDecode(dec, &bad); err != nil {
			return data, err
		}
		err = &bad
		return data, err
	}

	err = json.UnmarshalDecode(dec, &data)

	return data, err
}

// UpdateAccountContact updates the contacts for an account. The contacts parameter must contain contacts in a form
// supported by the ACME server. For example, Let's Encrypt accepts contacts of the form "mailto:example@example.com".
// On success, the returned error will be nil, but the returned [AccountData] object may or may not reflect the new
// contacts.
func (c Client) UpdateAccountContact(ctx context.Context, account Account, contacts []string) (AccountData, error) {
	var (
		err  error
		b    []byte
		bad  Problem
		dec  *jsontext.Decoder
		res  *http.Response
		data AccountData
	)

	if b, err = json.Marshal(&struct {
		Contact []string `json:"contact"`
	}{
		Contact: contacts,
	}); err != nil {
		return data, err
	}
	// here the account ID, or location, is the URL as well as the KID
	if res, err = c.signedPostID(ctx, account.ID, account.ID, account.Key.es256Key, b); err != nil {
		return data, err
	}

	defer func() {
		err = errors.Join(err, res.Body.Close())
	}()

	dec = jsontext.NewDecoder(res.Body)

	if res.StatusCode != http.StatusOK {
		if err = json.UnmarshalDecode(dec, &bad); err != nil {
			return data, err
		}
		err = &bad
		return data, err
	}

	err = json.UnmarshalDecode(dec, &data)

	return data, err
}

type keyRollover struct {
	AccountID string `json:"account"`
	OldKey    jwk    `json:"oldKey"`
}

func (c Client) UpdateAccountKey(ctx context.Context, account Account, newKey AccountKey) (Account, error) {
	var (
		out          Account
		err          error
		k            keyRollover
		innerPayload []byte
		payload      []byte
		bad          Problem
		dec          *jsontext.Decoder
		res          *http.Response
		j            jwk
		h            jwsHeaderNonceless
	)

	// The request consists of an outer jws, signed with the old key, that contains an inner jws, signed by the new key.
	// The inner jws has a payload consisting of the account ID and the old key's jwk.

	if j, err = account.Key.newJWK(); err != nil {
		return out, err
	}

	k = keyRollover{
		AccountID: account.ID,
		OldKey:    j,
	}

	if innerPayload, err = json.Marshal(&k); err != nil {
		return out, err
	}

	if h, err = newKey.newJWSHeaderNonceless(c.Dir.KeyChange); err != nil {
		return out, err
	}

	if payload, err = jwsBytes(newKey.es256Key, h, innerPayload); err != nil {
		return out, err
	}

	// We can now make a normal post request, signed by the old key.
	if res, err = c.signedPostID(ctx, c.Dir.KeyChange, account.ID, account.Key.es256Key, payload); err != nil {
		return out, err
	}

	defer func() {
		err = errors.Join(err, res.Body.Close())
	}()

	if res.StatusCode != http.StatusOK {
		dec = jsontext.NewDecoder(res.Body)
		if err = json.UnmarshalDecode(dec, &bad); err != nil {
			return out, err
		}
		err = &bad
		return out, err
	}

	out.ID = account.ID
	out.Key = newKey

	return out, err
}

func (c Client) newOrder(ctx context.Context, account Account, domainSlice []string, cfg OrderCfg) (order, error) {
	var (
		out order
		bad Problem
		err error
		raw []byte
		res *http.Response
		dec *jsontext.Decoder
	)

	if raw, err = json.Marshal(orderRequest{
		Identifiers: identifiers(domainSlice),
		NotBefore:   cfg.NotBefore,
		NotAfter:    cfg.NotAfter,
	}); err != nil {
		return out, err
	}

	if res, err = c.signedPostID(ctx, c.Dir.NewOrder, account.ID, account.Key.es256Key, raw); err != nil {
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

	return out, err
}

func (c Client) fetchUnmarshalAuthz(ctx context.Context, url, id string, key es256Key, out *authz) error {
	var (
		err error
		res *http.Response
		dec *jsontext.Decoder
		bad Problem
	)

	res, err = c.signedPostID(ctx, url, id, key, postAsGetPayload)
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
		out.retryAfter.parse(res)
	}

	return err
}

func (c Client) fetchChallenge(ctx context.Context, url, id string, key es256Key, payload []byte) (rawChallenge, error) {
	var (
		out rawChallenge
		res *http.Response
		dec *jsontext.Decoder
		bad Problem
		err error
	)

	if res, err = c.signedPostID(ctx, url, id, key, payload); err != nil {
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
			out.retryAfter.parse(res)
		}
	}

	return out, err
}

// fetchRawChallenge fetches the current state of a challenge without starting
// validation.
func (c Client) fetchRawChallenge(ctx context.Context, url, id string, key es256Key) (rawChallenge, error) {
	return c.fetchChallenge(ctx, url, id, key, []byte{})
}

// acceptChallenge tells the ACME server that the challenge response has been
// provisioned and that validation should begin. Per RFC 8555 section 7.5.1,
// this is a POST with an empty JSON object ("{}") to the challenge URL.
func (c Client) acceptChallenge(ctx context.Context, url, id string, key es256Key) (rawChallenge, error) {
	return c.fetchChallenge(ctx, url, id, key, []byte("{}"))
}

func (c Client) fetchAuthz(ctx context.Context, urls []string, id string, key es256Key) ([]authz, error) {
	var (
		err error
		i   int
		url string
		out = make([]authz, len(urls))
	)

	for i, url = range urls {
		if err = c.fetchUnmarshalAuthz(ctx, url, id, key, &out[i]); err != nil {
			return nil, err
		}
	}

	return out, nil
}

// NewClient fetches the ACME directory at url and returns a Client using log. If log is nil
// no logging is performed.
func NewClient(ctx context.Context, url string, log *slog.Logger) (Client, error) {
	var (
		c   Client
		err error
		req *http.Request
		res *http.Response
		dec *jsontext.Decoder
	)

	if req, err = http.NewRequest(http.MethodGet, url, nil); err != nil {
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

	if err = json.UnmarshalDecode(dec, &c.Dir); err != nil {
		return c, err
	}

	c.Log = log

	return c, nil
}

// OrderCertificate orders and returns a certificate for domains, using the mapped
// Providers for DNS-01 validation.
func (c Client) OrderCertificate(ctx context.Context, account Account, domains map[string]Provider, cfg OrderCfg) (Certificate, error) {
	if account.Key.pk == nil {
		return Certificate{}, errors.New("uninitialized account Key")
	}
	if account.ID == "" {
		return Certificate{}, errors.New("uninitialized account ID")
	}
	if len(domains) == 0 {
		return Certificate{}, errors.New("order must include at least 1 domain")
	}

	s := slices.Collect(maps.Keys(domains))

	o, err := c.newOrder(ctx, account, s, cfg)
	if err != nil {
		return Certificate{}, err
	}

	b, key, err := c.attempt(ctx, &o, account.ID, account.Key.es256Key, s, domains, cfg)
	if err != nil {
		return Certificate{}, err
	}

	if len(b) == 0 {
		return Certificate{}, errors.New("no certificate provided")
	}

	chain := parsePEMChain(b)

	out := make([]*x509.Certificate, len(chain))

	for i, der := range chain {
		if out[i], err = x509.ParseCertificate(der); err != nil {
			return Certificate{}, err
		}
	}

	return Certificate{
		PrivateKey: key,
		Chain:      out,
	}, nil
}

func parsePEMChain(b []byte) [][]byte {
	var (
		block *pem.Block
		chain [][]byte
	)

	for block, b = pem.Decode(b); block != nil; block, b = pem.Decode(b) {
		chain = append(chain, block.Bytes)

		if len(b) == 0 {
			return chain
		}
	}

	return chain
}
