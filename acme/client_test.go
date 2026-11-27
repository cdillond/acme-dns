package acme

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.ciaran.lol/acme-dns/acme/internal/fixtures"
)

func fixtureClient(srv *fixtures.Server) Client {
	return Client{
		Dir: ACMEDirectory{
			NewNonce:   srv.Endpoint("newNonce"),
			NewAccount: srv.Endpoint("newAccount"),
			NewOrder:   srv.Endpoint("newOrder"),
			KeyChange:  srv.Endpoint("keyChange"),
		},
		cache: new(nonceCache),
	}
}

func fixtureKey(t *testing.T) AccountKey {
	t.Helper()
	key, err := NewAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func testProblemJSON(t *testing.T, typ ProblemType) []byte {
	t.Helper()
	return fixtures.JSON(t, map[string]any{
		"type":  string(typ),
		"title": "test problem",
	})
}

func closedFixtureServer(t *testing.T) *fixtures.Server {
	t.Helper()
	srv := fixtures.NewServer(t)
	srv.Close()
	return srv
}

func requireProblemError(t *testing.T, err error, typ ProblemType) {
	t.Helper()
	var p *Problem
	if !errors.As(err, &p) {
		t.Fatalf("error = %T %v, want *Problem", err, err)
	}
	if p.Type != typ {
		t.Errorf("problem type = %q, want %q", p.Type, typ)
	}
}

func requireErrorContaining(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("error = %v, want %q", err, want)
	}
}

func TestNewClient(t *testing.T) {
	srv := fixtures.NewServer(t)
	srv.Respond(http.MethodGet, "/directory", fixtures.Response{
		Status: http.StatusOK,
		Body:   srv.Directory(t),
	})

	c, err := NewClient(context.Background(), srv.Endpoint("directory"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.Dir.NewAccount != srv.Endpoint("newAccount") {
		t.Errorf("NewAccount = %q", c.Dir.NewAccount)
	}
	if c.cache == nil {
		t.Error("NewClient did not initialize the nonce cache")
	}
}

func TestNewClientRejectsFailedDirectory(t *testing.T) {
	srv := fixtures.NewServer(t)
	if _, err := NewClient(context.Background(), srv.Endpoint("directory"), nil); err == nil {
		t.Error("NewClient accepted a non-200 directory response")
	}
}

func TestGetNonceFallsBackToServer(t *testing.T) {
	srv := fixtures.NewServer(t)
	c := Client{
		Dir:   ACMEDirectory{NewNonce: srv.Endpoint("newNonce")},
		cache: new(nonceCache),
	}

	nonce, err := c.getNonce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if nonce != fixtures.DefaultNonce {
		t.Errorf("nonce = %q, want %q", nonce, fixtures.DefaultNonce)
	}
}

func TestRequestAccount(t *testing.T) {
	key, err := NewAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	srv := fixtures.NewServer(t)
	srv.Respond(http.MethodPost, "/newAccount", fixtures.Response{
		Status: http.StatusCreated,
		Header: http.Header{
			"Replay-Nonce": []string{"nonce-2"},
			"Location":     []string{srv.Endpoint("acct/1")},
		},
		Body: fixtures.JSON(t, map[string]any{
			"status":  "valid",
			"contact": []string{"mailto:test@example.com"},
			"orders":  srv.Endpoint("orders"),
		}),
	})

	c := Client{
		Dir: ACMEDirectory{
			NewNonce:   srv.Endpoint("newNonce"),
			NewAccount: srv.Endpoint("newAccount"),
		},
		cache: new(nonceCache),
	}
	acc, data, err := c.RequestAccount(context.Background(), key, AccountCfg{
		Contact:              []string{"mailto:test@example.com"},
		TermsOfServiceAgreed: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	post := srv.LastRequest(http.MethodPost, "/newAccount")
	jws := post.JWS(t)

	t.Run("returned account", func(t *testing.T) {
		if acc.ID != srv.Endpoint("acct/1") {
			t.Errorf("account ID = %q", acc.ID)
		}
		if acc.Key.PrivateKey() != key.PrivateKey() {
			t.Error("returned account has the wrong key")
		}
		if data.Status != AccountStatusValid || len(data.Contact) != 1 || data.Contact[0] != "mailto:test@example.com" {
			t.Errorf("account data = %+v", data)
		}
	})

	t.Run("request headers", func(t *testing.T) {
		if got := post.Header.Get("Content-Type"); got != joseMIME {
			t.Errorf("content-type = %q, want %q", got, joseMIME)
		}
		if got := post.Header.Get("User-Agent"); got != UserAgent {
			t.Errorf("user-agent = %q, want %q", got, UserAgent)
		}
	})

	t.Run("protected header", func(t *testing.T) {
		var hdr struct {
			Alg   string `json:"alg"`
			URL   string `json:"url"`
			Nonce string `json:"nonce"`
			JWK   jwk    `json:"jwk"`
		}
		if err := json.Unmarshal(jws.ProtectedJSON, &hdr); err != nil {
			t.Fatal(err)
		}
		if hdr.Alg != "ES256" || hdr.URL != srv.Endpoint("newAccount") || hdr.Nonce != fixtures.DefaultNonce {
			t.Errorf("protected header = %+v", hdr)
		}
		if hdr.JWK.Kty != "EC" || hdr.JWK.Crv != "P-256" {
			t.Errorf("JWK = %+v", hdr.JWK)
		}
	})

	t.Run("signature", func(t *testing.T) {
		pk, ok := key.PrivateKey().(*ecdsa.PrivateKey)
		if !ok {
			t.Fatalf("key type = %T", key.PrivateKey())
		}
		if len(jws.Signature) != 64 {
			t.Fatalf("signature length = %d, want 64", len(jws.Signature))
		}
		digest := sha256.Sum256(jws.SigningInput)
		if !ecdsa.Verify(&pk.PublicKey, digest[:], new(big.Int).SetBytes(jws.Signature[:32]), new(big.Int).SetBytes(jws.Signature[32:])) {
			t.Error("JWS signature did not verify with the account public key")
		}
	})

	t.Run("payload", func(t *testing.T) {
		var cfg AccountCfg
		if err := json.Unmarshal(jws.Payload, &cfg); err != nil {
			t.Fatal(err)
		}
		if !cfg.TermsOfServiceAgreed || len(cfg.Contact) != 1 || cfg.Contact[0] != "mailto:test@example.com" {
			t.Errorf("request payload = %+v", cfg)
		}
	})
}

func TestSignedPostIDRetriesBadNonce(t *testing.T) {
	key, err := NewAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	srv := fixtures.NewServer(t)

	badBody := fixtures.JSON(t, map[string]any{
		"type":  string(ProblemTypeBadNonce),
		"title": "bad nonce",
	})
	okBody := fixtures.JSON(t, map[string]any{
		"status":      "pending",
		"identifiers": []any{map[string]any{"type": "dns", "value": "example.com"}},
	})
	srv.Handle(http.MethodPost, "/newOrder", func(*http.Request) fixtures.Response {
		if srv.Count(http.MethodPost, "/newOrder") == 1 {
			return fixtures.Response{
				Status: http.StatusBadRequest,
				Header: http.Header{"Replay-Nonce": []string{"nonce-2"}},
				Body:   badBody,
			}
		}
		return fixtures.Response{
			Status: http.StatusCreated,
			Header: http.Header{
				"Replay-Nonce": []string{"nonce-3"},
				"Location":     []string{srv.Endpoint("order/1")},
			},
			Body: okBody,
		}
	})

	c := Client{
		Dir: ACMEDirectory{
			NewNonce: srv.Endpoint("newNonce"),
			NewOrder: srv.Endpoint("newOrder"),
		},
		cache: new(nonceCache),
	}
	o, err := c.newOrder(context.Background(), Account{ID: "acct", Key: key}, []string{"example.com"}, OrderCfg{})
	if err != nil {
		t.Fatal(err)
	}
	if o.Status != orderStatusPending || o.location != srv.Endpoint("order/1") {
		t.Errorf("order = %+v", o)
	}

	posts := srv.Requests(http.MethodPost, "/newOrder")
	if len(posts) != 2 {
		t.Fatalf("POST count = %d, want 2", len(posts))
	}
	for i, wantNonce := range []string{fixtures.DefaultNonce, "nonce-2"} {
		var hdr struct {
			Nonce string `json:"nonce"`
		}
		if err = json.Unmarshal(posts[i].JWS(t).ProtectedJSON, &hdr); err != nil {
			t.Fatal(err)
		}
		if hdr.Nonce != wantNonce {
			t.Errorf("request %d nonce = %q, want %q", i+1, hdr.Nonce, wantNonce)
		}
	}

	// The nonce from the successful response is cached for the next request.
	if nonce, err := c.getNonce(context.Background()); err != nil || nonce != "nonce-3" {
		t.Errorf("cached nonce = %q, %v; want nonce-3", nonce, err)
	}
}

func TestSignedPostJWKRetriesBadNonce(t *testing.T) {
	key, err := NewAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	srv := fixtures.NewServer(t)

	badBody := fixtures.JSON(t, map[string]any{
		"type":  string(ProblemTypeBadNonce),
		"title": "bad nonce",
	})
	okBody := fixtures.JSON(t, map[string]any{"status": "valid"})
	srv.Handle(http.MethodPost, "/newAccount", func(*http.Request) fixtures.Response {
		if srv.Count(http.MethodPost, "/newAccount") == 1 {
			return fixtures.Response{
				Status: http.StatusBadRequest,
				Header: http.Header{"Replay-Nonce": []string{"nonce-2"}},
				Body:   badBody,
			}
		}
		return fixtures.Response{
			Status: http.StatusCreated,
			Header: http.Header{"Replay-Nonce": []string{"nonce-3"}},
			Body:   okBody,
		}
	})

	c := Client{
		Dir:   ACMEDirectory{NewNonce: srv.Endpoint("newNonce")},
		cache: new(nonceCache),
	}
	res, err := c.signedPostJWK(context.Background(), srv.Endpoint("newAccount"), key.es256Key, []byte(`{"example":"value"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusCreated {
		t.Errorf("status = %d, want %d", res.StatusCode, http.StatusCreated)
	}

	posts := srv.Requests(http.MethodPost, "/newAccount")
	if len(posts) != 2 {
		t.Fatalf("POST count = %d, want 2", len(posts))
	}
	for i, wantNonce := range []string{fixtures.DefaultNonce, "nonce-2"} {
		var hdr struct {
			Nonce string `json:"nonce"`
		}
		if err = json.Unmarshal(posts[i].JWS(t).ProtectedJSON, &hdr); err != nil {
			t.Fatal(err)
		}
		if hdr.Nonce != wantNonce {
			t.Errorf("request %d nonce = %q, want %q", i+1, hdr.Nonce, wantNonce)
		}
	}

	// The nonce from the successful response is cached for the next request.
	if nonce, err := c.getNonce(context.Background()); err != nil || nonce != "nonce-3" {
		t.Errorf("cached nonce = %q, %v; want nonce-3", nonce, err)
	}
}

func TestSignedPostIDRetriesExhausted(t *testing.T) {
	key, err := NewAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	srv := fixtures.NewServer(t)
	badBody := fixtures.JSON(t, map[string]any{"type": string(ProblemTypeBadNonce)})
	srv.Handle(http.MethodPost, "/newOrder", func(*http.Request) fixtures.Response {
		return fixtures.Response{
			Status: http.StatusBadRequest,
			Header: http.Header{"Replay-Nonce": []string{"nonce-2"}},
			Body:   badBody,
		}
	})

	c := Client{
		Dir: ACMEDirectory{
			NewNonce: srv.Endpoint("newNonce"),
			NewOrder: srv.Endpoint("newOrder"),
		},
		cache: new(nonceCache),
	}
	_, err = c.newOrder(context.Background(), Account{ID: "acct", Key: key}, []string{"example.com"}, OrderCfg{})
	if err == nil || !strings.Contains(err.Error(), "retries exhausted") {
		t.Fatalf("error = %v, want retries exhausted", err)
	}
	if got := srv.Count(http.MethodPost, "/newOrder"); got != 5 {
		t.Errorf("POST count = %d, want 5", got)
	}
}

func TestSignedPostJWKRetriesExhausted(t *testing.T) {
	key, err := NewAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	srv := fixtures.NewServer(t)
	badBody := fixtures.JSON(t, map[string]any{"type": string(ProblemTypeBadNonce)})
	srv.Respond(http.MethodPost, "/newAccount", fixtures.Response{
		Status: http.StatusBadRequest,
		Header: http.Header{"Replay-Nonce": []string{"nonce-2"}},
		Body:   badBody,
	})

	c := Client{
		Dir:   ACMEDirectory{NewNonce: srv.Endpoint("newNonce")},
		cache: new(nonceCache),
	}
	_, err = c.signedPostJWK(context.Background(), srv.Endpoint("newAccount"), key.es256Key, []byte(`{"example":"value"}`))
	if err == nil || !strings.Contains(err.Error(), "retries exhausted") {
		t.Fatalf("error = %v, want retries exhausted", err)
	}
	if got := srv.Count(http.MethodPost, "/newAccount"); got != 5 {
		t.Errorf("POST count = %d, want 5", got)
	}
}

type closeTrackingBody struct {
	io.Reader
	closed bool
}

func (b *closeTrackingBody) Close() error {
	b.closed = true
	return nil
}

func TestCheckResponseProblem(t *testing.T) {
	problemJSON := `{"type":"urn:ietf:params:acme:error:unauthorized","title":"no permission","status":403}`

	t.Run("success leaves body open", func(t *testing.T) {
		body := &closeTrackingBody{Reader: strings.NewReader("")}
		x, err := checkResponseProblem(&http.Response{StatusCode: http.StatusOK, Body: body})
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := x.(checkResultOK); !ok {
			t.Fatalf("result type = %T, want checkResultOK", x)
		}
		if body.closed {
			t.Error("body was closed on success")
		}
	})

	t.Run("problem becomes an error", func(t *testing.T) {
		body := &closeTrackingBody{Reader: strings.NewReader(problemJSON)}
		x, err := checkResponseProblem(&http.Response{StatusCode: http.StatusForbidden, Body: body})
		if x != nil {
			t.Fatalf("result = %v, want nil", x)
		}
		var p *Problem
		if !errors.As(err, &p) {
			t.Fatalf("error type = %T, want *Problem", err)
		}
		if p.Type != ProblemTypeUnauthorized || p.Title != "no permission" {
			t.Errorf("problem = %+v", p)
		}
		if !strings.Contains(p.Error(), "no permission") {
			t.Errorf("Problem.Error() = %q", p.Error())
		}
		if !body.closed {
			t.Error("body was not closed on error")
		}
	})

	t.Run("bad nonce is retryable", func(t *testing.T) {
		body := &closeTrackingBody{Reader: strings.NewReader(`{"type":"urn:ietf:params:acme:error:badNonce"}`)}
		res := &http.Response{StatusCode: http.StatusBadRequest, Body: body, Header: http.Header{}}
		res.Header.Set("Replay-Nonce", "fresh-nonce")
		x, err := checkResponseProblem(res)
		if err != nil {
			t.Fatal(err)
		}
		if got, ok := x.(checkResultRetry); !ok || string(got) != "fresh-nonce" {
			t.Fatalf("result = %v, want checkResultRetry(fresh-nonce)", x)
		}
		if !body.closed {
			t.Error("body was not closed on retry")
		}
	})

	t.Run("bad nonce without valid replay nonce is an error", func(t *testing.T) {
		body := &closeTrackingBody{Reader: strings.NewReader(`{"type":"urn:ietf:params:acme:error:badNonce"}`)}
		_, err := checkResponseProblem(&http.Response{StatusCode: http.StatusBadRequest, Body: body, Header: http.Header{}})
		if err == nil {
			t.Error("bad nonce without Replay-Nonce was not an error")
		}
	})

	t.Run("malformed problem body", func(t *testing.T) {
		res := &http.Response{StatusCode: http.StatusInternalServerError, Body: io.NopCloser(strings.NewReader("not json")), Status: "500"}
		_, err := checkResponseProblem(res)
		if err == nil || !strings.Contains(err.Error(), "server responded with status") {
			t.Fatalf("error = %v, want status error", err)
		}
	})
}

func TestOrderCertificateValidatesEmptyDomains(t *testing.T) {
	key, err := NewAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	account := Account{
		ID:  "https://example.com/acct/1",
		Key: key,
	}

	_, err = (Client{}).OrderCertificate(context.Background(), account, nil, OrderCfg{})
	if err == nil {
		t.Fatal("OrderCertificate accepted an empty domain set")
	}
	if !strings.Contains(err.Error(), "at least 1 domain") {
		t.Fatalf("error = %q, want empty domain error", err)
	}
}

func TestRequestAccountWithEABValidation(t *testing.T) {
	key, err := NewAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		eab  EABRequest
		want string
	}{
		{"missing KID", EABRequest{Alg: "HS256", Hash: hmac.New(sha256.New, []byte("secret"))}, "KID"},
		{"missing Alg", EABRequest{KID: "kid", Hash: hmac.New(sha256.New, []byte("secret"))}, "Alg"},
		{"missing Hash", EABRequest{KID: "kid", Alg: "HS256"}, "Hash"},
	}
	for _, tc := range cases {
		_, _, err := (Client{}).RequestAccountWithEAB(context.Background(), key, tc.eab, AccountCfg{})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error = %v, want %q", tc.name, err, tc.want)
		}
	}
}

func TestRequestAccountWithEAB(t *testing.T) {
	key, err := NewAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("eab-secret")

	srv := fixtures.NewServer(t)
	srv.Respond(http.MethodPost, "/newAccount", fixtures.Response{
		Status: http.StatusCreated,
		Header: http.Header{"Location": []string{srv.Endpoint("acct/1")}},
		Body:   fixtures.JSON(t, map[string]any{"status": "valid"}),
	})

	c := Client{
		Dir: ACMEDirectory{
			NewNonce:   srv.Endpoint("newNonce"),
			NewAccount: srv.Endpoint("newAccount"),
		},
		cache: new(nonceCache),
	}
	acc, _, err := c.RequestAccountWithEAB(context.Background(), key, EABRequest{
		KID:  "eab-kid",
		Alg:  "HS256",
		Hash: hmac.New(sha256.New, secret),
	}, AccountCfg{Contact: []string{"mailto:test@example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if acc.ID != srv.Endpoint("acct/1") {
		t.Errorf("account ID = %q", acc.ID)
	}

	jws := srv.LastRequest(http.MethodPost, "/newAccount").JWS(t)
	var payload struct {
		ExternalAccountBinding jwsDto   `json:"externalAccountBinding"`
		Contact                []string `json:"contact"`
	}
	if err = json.Unmarshal(jws.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Contact) != 1 || payload.Contact[0] != "mailto:test@example.com" {
		t.Errorf("account payload = %+v", payload)
	}

	eab := payload.ExternalAccountBinding
	protected, err := base64.RawURLEncoding.DecodeString(eab.Protected)
	if err != nil {
		t.Fatal(err)
	}
	var hdr jwsMACHeader
	if err = json.Unmarshal(protected, &hdr); err != nil {
		t.Fatal(err)
	}
	if hdr.Alg != "HS256" || hdr.KID != "eab-kid" || hdr.URL != srv.Endpoint("newAccount") {
		t.Errorf("EAB protected header = %+v", hdr)
	}

	sig, err := base64.RawURLEncoding.DecodeString(eab.Sig)
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(eab.Protected + "." + eab.Payload))
	if !hmac.Equal(sig, mac.Sum(nil)) {
		t.Error("external account binding MAC did not verify")
	}

	jwk, err := key.newJWK()
	if err != nil {
		t.Fatal(err)
	}
	wantPayload, err := json.Marshal(&jwk, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	gotPayload, err := base64.RawURLEncoding.DecodeString(eab.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotPayload, wantPayload) {
		t.Errorf("EAB payload = %q, want %q", gotPayload, wantPayload)
	}
}

func TestDeactivateAccount(t *testing.T) {
	key, err := NewAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	srv := fixtures.NewServer(t)
	accountID := srv.Endpoint("acct/1")
	srv.Respond(http.MethodPost, "/acct/1", fixtures.Response{
		Status: http.StatusOK,
		Header: http.Header{"Replay-Nonce": []string{"nonce-2"}},
		Body:   fixtures.JSON(t, map[string]any{"status": "deactivated"}),
	})

	c := Client{
		Dir:   ACMEDirectory{NewNonce: srv.Endpoint("newNonce")},
		cache: new(nonceCache),
	}
	data, err := c.DeactivateAccount(context.Background(), Account{ID: accountID, Key: key})
	if err != nil {
		t.Fatal(err)
	}
	if data.Status != AccountStatusDeactivated {
		t.Errorf("status = %d, want deactivated", data.Status)
	}

	post := srv.LastRequest(http.MethodPost, "/acct/1")
	jws := post.JWS(t)
	var hdr struct {
		Alg   string `json:"alg"`
		URL   string `json:"url"`
		Nonce string `json:"nonce"`
		KID   string `json:"kid"`
	}
	if err = json.Unmarshal(jws.ProtectedJSON, &hdr); err != nil {
		t.Fatal(err)
	}
	if hdr.Alg != "ES256" || hdr.URL != accountID || hdr.Nonce != fixtures.DefaultNonce || hdr.KID != accountID {
		t.Errorf("protected header = %+v", hdr)
	}

	var payload struct {
		Status AccountStatus `json:"status"`
	}
	if err = json.Unmarshal(jws.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Status != AccountStatusDeactivated {
		t.Errorf("request status = %d, want deactivated", payload.Status)
	}
}

func TestUpdateAccountContact(t *testing.T) {
	key, err := NewAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	contacts := []string{"mailto:old@example.com", "mailto:new@example.com"}
	srv := fixtures.NewServer(t)
	accountID := srv.Endpoint("acct/1")
	srv.Respond(http.MethodPost, "/acct/1", fixtures.Response{
		Status: http.StatusOK,
		Header: http.Header{"Replay-Nonce": []string{"nonce-2"}},
		Body: fixtures.JSON(t, map[string]any{
			"status":  "valid",
			"contact": contacts,
		}),
	})

	c := Client{
		Dir:   ACMEDirectory{NewNonce: srv.Endpoint("newNonce")},
		cache: new(nonceCache),
	}
	data, err := c.UpdateAccountContact(context.Background(), Account{ID: accountID, Key: key}, contacts)
	if err != nil {
		t.Fatal(err)
	}
	if data.Status != AccountStatusValid || len(data.Contact) != len(contacts) {
		t.Fatalf("account data = %+v", data)
	}
	for i := range contacts {
		if data.Contact[i] != contacts[i] {
			t.Errorf("contact %d = %q, want %q", i, data.Contact[i], contacts[i])
		}
	}

	post := srv.LastRequest(http.MethodPost, "/acct/1")
	jws := post.JWS(t)
	var hdr struct {
		Alg   string `json:"alg"`
		URL   string `json:"url"`
		Nonce string `json:"nonce"`
		KID   string `json:"kid"`
	}
	if err = json.Unmarshal(jws.ProtectedJSON, &hdr); err != nil {
		t.Fatal(err)
	}
	if hdr.Alg != "ES256" || hdr.URL != accountID || hdr.Nonce != fixtures.DefaultNonce || hdr.KID != accountID {
		t.Errorf("protected header = %+v", hdr)
	}

	var payload struct {
		Contact []string `json:"contact"`
	}
	if err = json.Unmarshal(jws.Payload, &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Contact) != len(contacts) {
		t.Fatalf("request contacts = %+v, want %+v", payload.Contact, contacts)
	}
	for i := range contacts {
		if payload.Contact[i] != contacts[i] {
			t.Errorf("request contact %d = %q, want %q", i, payload.Contact[i], contacts[i])
		}
	}
}

func TestUpdateAccountKey(t *testing.T) {
	oldKey, err := NewAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	newKey, err := NewAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	srv := fixtures.NewServer(t)
	accountID := srv.Endpoint("acct/1")
	keyChange := srv.Endpoint("keyChange")
	srv.Respond(http.MethodPost, "/keyChange", fixtures.Response{
		Status: http.StatusOK,
		Header: http.Header{"Replay-Nonce": []string{"nonce-2"}},
	})

	c := Client{
		Dir: ACMEDirectory{
			NewNonce:  srv.Endpoint("newNonce"),
			KeyChange: keyChange,
		},
		cache: new(nonceCache),
	}
	account := Account{ID: accountID, Key: oldKey}
	got, err := c.UpdateAccountKey(context.Background(), account, newKey)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != accountID || got.Key.PrivateKey() != newKey.PrivateKey() {
		t.Errorf("returned account = %+v, want ID %q and the new key", got, accountID)
	}

	outer := srv.LastRequest(http.MethodPost, "/keyChange").JWS(t)
	var outerHdr struct {
		Alg   string `json:"alg"`
		URL   string `json:"url"`
		Nonce string `json:"nonce"`
		KID   string `json:"kid"`
	}
	if err = json.Unmarshal(outer.ProtectedJSON, &outerHdr); err != nil {
		t.Fatal(err)
	}
	if outerHdr.Alg != "ES256" || outerHdr.URL != keyChange || outerHdr.Nonce != fixtures.DefaultNonce || outerHdr.KID != accountID {
		t.Errorf("outer protected header = %+v", outerHdr)
	}

	var inner jwsDto
	if err = json.Unmarshal(outer.Payload, &inner); err != nil {
		t.Fatal(err)
	}
	innerProtected, err := base64.RawURLEncoding.DecodeString(inner.Protected)
	if err != nil {
		t.Fatal(err)
	}
	innerPayload, err := base64.RawURLEncoding.DecodeString(inner.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var innerHdr jwsHeaderNonceless
	if err = json.Unmarshal(innerProtected, &innerHdr); err != nil {
		t.Fatal(err)
	}
	wantNewJWK, err := newKey.newJWK()
	if err != nil {
		t.Fatal(err)
	}
	if innerHdr.Alg != "ES256" || innerHdr.URL != keyChange || innerHdr.JWK != wantNewJWK {
		t.Errorf("inner protected header = %+v", innerHdr)
	}

	var rollover keyRollover
	if err = json.Unmarshal(innerPayload, &rollover); err != nil {
		t.Fatal(err)
	}
	wantOldJWK, err := oldKey.newJWK()
	if err != nil {
		t.Fatal(err)
	}
	if rollover.AccountID != accountID || rollover.OldKey != wantOldJWK {
		t.Errorf("rollover payload = %+v", rollover)
	}

	innerSig, err := base64.RawURLEncoding.DecodeString(inner.Sig)
	if err != nil {
		t.Fatal(err)
	}
	if len(innerSig) != 64 {
		t.Fatalf("inner signature length = %d, want 64", len(innerSig))
	}
	pk, ok := newKey.PrivateKey().(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("new key type = %T", newKey.PrivateKey())
	}
	digest := sha256.Sum256([]byte(inner.Protected + "." + inner.Payload))
	if !ecdsa.Verify(&pk.PublicKey, digest[:], new(big.Int).SetBytes(innerSig[:32]), new(big.Int).SetBytes(innerSig[32:])) {
		t.Error("inner JWS signature did not verify with the new key")
	}
}

func TestFetchUnmarshalAuthz(t *testing.T) {
	key, err := NewAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	srv := fixtures.NewServer(t)
	authzURL := srv.Endpoint("authz/1")
	accountID := srv.Endpoint("acct/1")
	srv.Respond(http.MethodPost, "/authz/1", fixtures.Response{
		Status: http.StatusOK,
		Header: http.Header{
			"Replay-Nonce": []string{"nonce-2"},
			"Retry-After":  []string{"30"},
		},
		Body: fixtures.JSON(t, map[string]any{
			"identifier": map[string]any{"type": "dns", "value": "example.com"},
			"status":     "pending",
			"challenges": []any{map[string]any{
				"type":   "dns-01",
				"url":    srv.Endpoint("chall/1"),
				"status": "pending",
				"token":  "token-1",
			}},
		}),
	})

	c := Client{
		Dir:   ACMEDirectory{NewNonce: srv.Endpoint("newNonce")},
		cache: new(nonceCache),
	}
	var out authz
	if err = c.fetchUnmarshalAuthz(context.Background(), authzURL, accountID, key.es256Key, &out); err != nil {
		t.Fatal(err)
	}
	if out.Identifier.Type != "dns" || out.Identifier.Value != "example.com" || out.Status != authzStatusPending {
		t.Errorf("authorization = %+v", out)
	}
	if len(out.Challenges) != 1 || out.Challenges[0].Type != "dns-01" || out.Challenges[0].Status != challengeStatusPending || out.Challenges[0].Token != "token-1" {
		t.Errorf("challenges = %+v", out.Challenges)
	}
	if wait := time.Until(time.Time(out.retryAfter)); wait <= 29*time.Second || wait > 31*time.Second {
		t.Errorf("retry after = %v, want about 30s", wait)
	}

	jws := srv.LastRequest(http.MethodPost, "/authz/1").JWS(t)
	if len(jws.Payload) != 0 {
		t.Errorf("POST-as-GET payload = %q, want empty", jws.Payload)
	}
	var hdr struct {
		Alg   string `json:"alg"`
		URL   string `json:"url"`
		Nonce string `json:"nonce"`
		KID   string `json:"kid"`
	}
	if err = json.Unmarshal(jws.ProtectedJSON, &hdr); err != nil {
		t.Fatal(err)
	}
	if hdr.Alg != "ES256" || hdr.URL != authzURL || hdr.Nonce != fixtures.DefaultNonce || hdr.KID != accountID {
		t.Errorf("protected header = %+v", hdr)
	}
}

func TestFetchChallenge(t *testing.T) {
	key, err := NewAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	srv := fixtures.NewServer(t)
	challengeURL := srv.Endpoint("chall/1")
	accountID := srv.Endpoint("acct/1")
	srv.Respond(http.MethodPost, "/chall/1", fixtures.Response{
		Status: http.StatusOK,
		Header: http.Header{
			"Replay-Nonce": []string{"nonce-2"},
			"Retry-After":  []string{"15"},
		},
		Body: fixtures.JSON(t, map[string]any{
			"type":   "dns-01",
			"url":    challengeURL,
			"status": "processing",
			"token":  "token-2",
		}),
	})

	c := Client{
		Dir:   ACMEDirectory{NewNonce: srv.Endpoint("newNonce")},
		cache: new(nonceCache),
	}
	payload := []byte(`{"trigger":"validation"}`)
	out, err := c.fetchChallenge(context.Background(), challengeURL, accountID, key.es256Key, payload)
	if err != nil {
		t.Fatal(err)
	}
	if out.Type != "dns-01" || out.URL != challengeURL || out.Status != challengeStatusProcessing || out.Token != "token-2" {
		t.Errorf("challenge = %+v", out)
	}
	if wait := time.Until(time.Time(out.retryAfter)); wait <= 14*time.Second || wait > 16*time.Second {
		t.Errorf("retry after = %v, want about 15s", wait)
	}

	jws := srv.LastRequest(http.MethodPost, "/chall/1").JWS(t)
	if !bytes.Equal(jws.Payload, payload) {
		t.Errorf("payload = %q, want %q", jws.Payload, payload)
	}
	var hdr struct {
		Alg   string `json:"alg"`
		URL   string `json:"url"`
		Nonce string `json:"nonce"`
		KID   string `json:"kid"`
	}
	if err = json.Unmarshal(jws.ProtectedJSON, &hdr); err != nil {
		t.Fatal(err)
	}
	if hdr.Alg != "ES256" || hdr.URL != challengeURL || hdr.Nonce != fixtures.DefaultNonce || hdr.KID != accountID {
		t.Errorf("protected header = %+v", hdr)
	}
}

func TestFetchRawChallenge(t *testing.T) {
	key, err := NewAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	srv := fixtures.NewServer(t)
	challengeURL := srv.Endpoint("chall/2")
	accountID := srv.Endpoint("acct/1")
	srv.Respond(http.MethodPost, "/chall/2", fixtures.Response{
		Status: http.StatusOK,
		Body: fixtures.JSON(t, map[string]any{
			"type":   "dns-01",
			"url":    challengeURL,
			"status": "pending",
			"token":  "token-3",
		}),
	})

	c := Client{
		Dir:   ACMEDirectory{NewNonce: srv.Endpoint("newNonce")},
		cache: new(nonceCache),
	}
	out, err := c.fetchRawChallenge(context.Background(), challengeURL, accountID, key.es256Key)
	if err != nil {
		t.Fatal(err)
	}
	if out.Type != "dns-01" || out.URL != challengeURL || out.Status != challengeStatusPending || out.Token != "token-3" {
		t.Errorf("challenge = %+v", out)
	}
	jws := srv.LastRequest(http.MethodPost, "/chall/2").JWS(t)
	if len(jws.Payload) != 0 {
		t.Errorf("payload = %q, want empty", jws.Payload)
	}
}

func TestFetchAuthz(t *testing.T) {
	key, err := NewAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	srv := fixtures.NewServer(t)
	accountID := srv.Endpoint("acct/1")
	for i, name := range []string{"one.example.com", "two.example.com"} {
		srv.Respond(http.MethodPost, "/authz/"+strconv.Itoa(i+1), fixtures.Response{
			Status: http.StatusOK,
			Body: fixtures.JSON(t, map[string]any{
				"identifier": map[string]any{"type": "dns", "value": name},
				"status":     "valid",
			}),
		})
	}

	c := Client{
		Dir:   ACMEDirectory{NewNonce: srv.Endpoint("newNonce")},
		cache: new(nonceCache),
	}
	urls := []string{srv.Endpoint("authz/1"), srv.Endpoint("authz/2")}
	out, err := c.fetchAuthz(context.Background(), urls, accountID, key.es256Key)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("authorizations = %d, want 2", len(out))
	}
	for i, want := range []string{"one.example.com", "two.example.com"} {
		if out[i].Identifier.Value != want || out[i].Status != authzStatusValid {
			t.Errorf("authorization %d = %+v, want %s valid", i, out[i], want)
		}
	}
	if got := srv.Count(http.MethodPost, "/authz/1"); got != 1 {
		t.Errorf("first authz POST count = %d, want 1", got)
	}
	if got := srv.Count(http.MethodPost, "/authz/2"); got != 1 {
		t.Errorf("second authz POST count = %d, want 1", got)
	}
}

func testEABRequest() EABRequest {
	return EABRequest{
		KID:  "eab-kid",
		Alg:  "HS256",
		Hash: hmac.New(sha256.New, []byte("eab-secret")),
	}
}

func fixtureAuthzBody(t *testing.T, name string, status string) []byte {
	t.Helper()
	return fixtures.JSON(t, map[string]any{
		"identifier": map[string]any{"type": "dns", "value": name},
		"status":     status,
	})
}

func TestNewClientErrors(t *testing.T) {
	t.Run("transport error", func(t *testing.T) {
		srv := closedFixtureServer(t)
		_, err := NewClient(context.Background(), srv.Endpoint("directory"), nil)
		if err == nil {
			t.Error("NewClient accepted an unreachable directory URL")
		}
	})

	t.Run("error response with problem document", func(t *testing.T) {
		srv := fixtures.NewServer(t)
		srv.Respond(http.MethodGet, "/directory", fixtures.Response{
			Status: http.StatusForbidden,
			Body:   testProblemJSON(t, ProblemTypeUnauthorized),
		})
		_, err := NewClient(context.Background(), srv.Endpoint("directory"), nil)
		requireErrorContaining(t, err, "unexpected status")
	})

	t.Run("invalid body", func(t *testing.T) {
		srv := fixtures.NewServer(t)
		srv.Respond(http.MethodGet, "/directory", fixtures.Response{
			Status: http.StatusOK,
			Body:   []byte("not json"),
		})
		_, err := NewClient(context.Background(), srv.Endpoint("directory"), nil)
		if err == nil {
			t.Error("NewClient accepted a malformed directory")
		}
	})

	t.Run("unexpected success status", func(t *testing.T) {
		srv := fixtures.NewServer(t)
		srv.Respond(http.MethodGet, "/directory", fixtures.Response{
			Status: http.StatusCreated,
			Body:   srv.Directory(t),
		})
		_, err := NewClient(context.Background(), srv.Endpoint("directory"), nil)
		requireErrorContaining(t, err, "unexpected status")
	})
}

func TestRequestNonceErrors(t *testing.T) {
	t.Run("transport error", func(t *testing.T) {
		srv := closedFixtureServer(t)
		c := fixtureClient(srv)
		_, err := c.getNonce(context.Background())
		if err == nil {
			t.Error("getNonce succeeded against an unreachable server")
		}
	})

	t.Run("missing Replay-Nonce", func(t *testing.T) {
		srv := fixtures.NewServer(t)
		srv.Respond(http.MethodHead, "/newNonce", fixtures.Response{Status: http.StatusNoContent})
		c := fixtureClient(srv)
		_, err := c.getNonce(context.Background())
		requireErrorContaining(t, err, "no nonce")
	})
}

func TestSignedPostIDErrors(t *testing.T) {
	t.Run("transport error", func(t *testing.T) {
		srv := closedFixtureServer(t)
		key := fixtureKey(t)
		c := fixtureClient(srv)
		_, err := c.signedPostID(context.Background(), srv.Endpoint("newOrder"), "acct/1", key.es256Key, []byte(`{}`))
		if err == nil {
			t.Error("signedPostID succeeded against an unreachable server")
		}
	})

	t.Run("error response with problem document", func(t *testing.T) {
		srv := fixtures.NewServer(t)
		srv.Respond(http.MethodPost, "/newOrder", fixtures.Response{
			Status: http.StatusForbidden,
			Body:   testProblemJSON(t, ProblemTypeUnauthorized),
		})
		key := fixtureKey(t)
		c := fixtureClient(srv)
		_, err := c.signedPostID(context.Background(), srv.Endpoint("newOrder"), "acct/1", key.es256Key, []byte(`{}`))
		requireProblemError(t, err, ProblemTypeUnauthorized)
	})

	t.Run("invalid problem document", func(t *testing.T) {
		srv := fixtures.NewServer(t)
		srv.Respond(http.MethodPost, "/newOrder", fixtures.Response{
			Status: http.StatusInternalServerError,
			Body:   []byte("not json"),
		})
		key := fixtureKey(t)
		c := fixtureClient(srv)
		_, err := c.signedPostID(context.Background(), srv.Endpoint("newOrder"), "acct/1", key.es256Key, []byte(`{}`))
		requireErrorContaining(t, err, "server responded with status")
	})

	t.Run("bad nonce without Replay-Nonce", func(t *testing.T) {
		srv := fixtures.NewServer(t)
		srv.Respond(http.MethodPost, "/newOrder", fixtures.Response{
			Status: http.StatusBadRequest,
			Body:   testProblemJSON(t, ProblemTypeBadNonce),
		})
		key := fixtureKey(t)
		c := fixtureClient(srv)
		_, err := c.signedPostID(context.Background(), srv.Endpoint("newOrder"), "acct/1", key.es256Key, []byte(`{}`))
		requireErrorContaining(t, err, "no nonce")
	})
}

func TestSignedPostJWKErrors(t *testing.T) {
	t.Run("transport error", func(t *testing.T) {
		srv := closedFixtureServer(t)
		key := fixtureKey(t)
		c := fixtureClient(srv)
		_, err := c.signedPostJWK(context.Background(), srv.Endpoint("newAccount"), key.es256Key, []byte(`{}`))
		if err == nil {
			t.Error("signedPostJWK succeeded against an unreachable server")
		}
	})

	t.Run("error response with problem document", func(t *testing.T) {
		srv := fixtures.NewServer(t)
		srv.Respond(http.MethodPost, "/newAccount", fixtures.Response{
			Status: http.StatusForbidden,
			Body:   testProblemJSON(t, ProblemTypeUnauthorized),
		})
		key := fixtureKey(t)
		c := fixtureClient(srv)
		_, err := c.signedPostJWK(context.Background(), srv.Endpoint("newAccount"), key.es256Key, []byte(`{}`))
		requireProblemError(t, err, ProblemTypeUnauthorized)
	})

	t.Run("invalid problem document", func(t *testing.T) {
		srv := fixtures.NewServer(t)
		srv.Respond(http.MethodPost, "/newAccount", fixtures.Response{
			Status: http.StatusInternalServerError,
			Body:   []byte("not json"),
		})
		key := fixtureKey(t)
		c := fixtureClient(srv)
		_, err := c.signedPostJWK(context.Background(), srv.Endpoint("newAccount"), key.es256Key, []byte(`{}`))
		requireErrorContaining(t, err, "server responded with status")
	})

	t.Run("bad nonce without Replay-Nonce", func(t *testing.T) {
		srv := fixtures.NewServer(t)
		srv.Respond(http.MethodPost, "/newAccount", fixtures.Response{
			Status: http.StatusBadRequest,
			Body:   testProblemJSON(t, ProblemTypeBadNonce),
		})
		key := fixtureKey(t)
		c := fixtureClient(srv)
		_, err := c.signedPostJWK(context.Background(), srv.Endpoint("newAccount"), key.es256Key, []byte(`{}`))
		requireErrorContaining(t, err, "no nonce")
	})
}

func TestRequestAccountErrors(t *testing.T) {
	t.Run("transport error", func(t *testing.T) {
		srv := closedFixtureServer(t)
		key := fixtureKey(t)
		c := fixtureClient(srv)
		_, _, err := c.RequestAccount(context.Background(), key, AccountCfg{})
		if err == nil {
			t.Error("RequestAccount succeeded against an unreachable server")
		}
	})

	t.Run("error response with problem document", func(t *testing.T) {
		srv := fixtures.NewServer(t)
		srv.Respond(http.MethodPost, "/newAccount", fixtures.Response{
			Status: http.StatusForbidden,
			Body:   testProblemJSON(t, ProblemTypeUnauthorized),
		})
		key := fixtureKey(t)
		c := fixtureClient(srv)
		_, _, err := c.RequestAccount(context.Background(), key, AccountCfg{})
		requireProblemError(t, err, ProblemTypeUnauthorized)
	})

	t.Run("invalid body", func(t *testing.T) {
		srv := fixtures.NewServer(t)
		srv.Respond(http.MethodPost, "/newAccount", fixtures.Response{
			Status: http.StatusCreated,
			Header: http.Header{"Location": []string{srv.Endpoint("acct/1")}},
			Body:   []byte("not json"),
		})
		key := fixtureKey(t)
		c := fixtureClient(srv)
		_, _, err := c.RequestAccount(context.Background(), key, AccountCfg{})
		if err == nil {
			t.Error("RequestAccount accepted a malformed account body")
		}
	})

	t.Run("missing account ID", func(t *testing.T) {
		srv := fixtures.NewServer(t)
		srv.Respond(http.MethodPost, "/newAccount", fixtures.Response{
			Status: http.StatusCreated,
			Body:   fixtures.JSON(t, map[string]any{"status": "valid"}),
		})
		key := fixtureKey(t)
		c := fixtureClient(srv)
		_, _, err := c.RequestAccount(context.Background(), key, AccountCfg{})
		requireErrorContaining(t, err, "no account ID")
	})

	t.Run("unexpected success status", func(t *testing.T) {
		srv := fixtures.NewServer(t)
		srv.Respond(http.MethodPost, "/newAccount", fixtures.Response{
			Status: http.StatusAccepted,
			Header: http.Header{"Location": []string{srv.Endpoint("acct/1")}},
			Body:   fixtures.JSON(t, map[string]any{"status": "valid"}),
		})
		key := fixtureKey(t)
		c := fixtureClient(srv)
		_, _, err := c.RequestAccount(context.Background(), key, AccountCfg{})
		requireErrorContaining(t, err, "unexpected status")
	})
}

func TestRequestAccountWithEABErrors(t *testing.T) {
	t.Run("transport error", func(t *testing.T) {
		srv := closedFixtureServer(t)
		key := fixtureKey(t)
		c := fixtureClient(srv)
		_, _, err := c.RequestAccountWithEAB(context.Background(), key, testEABRequest(), AccountCfg{})
		if err == nil {
			t.Error("RequestAccountWithEAB succeeded against an unreachable server")
		}
	})

	t.Run("error response with problem document", func(t *testing.T) {
		srv := fixtures.NewServer(t)
		srv.Respond(http.MethodPost, "/newAccount", fixtures.Response{
			Status: http.StatusForbidden,
			Body:   testProblemJSON(t, ProblemTypeUnauthorized),
		})
		key := fixtureKey(t)
		c := fixtureClient(srv)
		_, _, err := c.RequestAccountWithEAB(context.Background(), key, testEABRequest(), AccountCfg{})
		requireProblemError(t, err, ProblemTypeUnauthorized)
	})

	t.Run("invalid body", func(t *testing.T) {
		srv := fixtures.NewServer(t)
		srv.Respond(http.MethodPost, "/newAccount", fixtures.Response{
			Status: http.StatusCreated,
			Header: http.Header{"Location": []string{srv.Endpoint("acct/1")}},
			Body:   []byte("not json"),
		})
		key := fixtureKey(t)
		c := fixtureClient(srv)
		_, _, err := c.RequestAccountWithEAB(context.Background(), key, testEABRequest(), AccountCfg{})
		if err == nil {
			t.Error("RequestAccountWithEAB accepted a malformed account body")
		}
	})

	t.Run("missing account ID", func(t *testing.T) {
		srv := fixtures.NewServer(t)
		srv.Respond(http.MethodPost, "/newAccount", fixtures.Response{
			Status: http.StatusCreated,
			Body:   fixtures.JSON(t, map[string]any{"status": "valid"}),
		})
		key := fixtureKey(t)
		c := fixtureClient(srv)
		_, _, err := c.RequestAccountWithEAB(context.Background(), key, testEABRequest(), AccountCfg{})
		requireErrorContaining(t, err, "no account ID")
	})

	t.Run("unexpected success status", func(t *testing.T) {
		srv := fixtures.NewServer(t)
		srv.Respond(http.MethodPost, "/newAccount", fixtures.Response{
			Status: http.StatusAccepted,
			Header: http.Header{"Location": []string{srv.Endpoint("acct/1")}},
			Body:   fixtures.JSON(t, map[string]any{"status": "valid"}),
		})
		key := fixtureKey(t)
		c := fixtureClient(srv)
		_, _, err := c.RequestAccountWithEAB(context.Background(), key, testEABRequest(), AccountCfg{})
		requireErrorContaining(t, err, "unexpected status")
	})
}

func fixtureAccount(t *testing.T, srv *fixtures.Server) Account {
	t.Helper()
	return Account{ID: srv.Endpoint("acct/1"), Key: fixtureKey(t)}
}

func fixtureOrderBody(t *testing.T) []byte {
	t.Helper()
	return fixtures.JSON(t, map[string]any{
		"status":      "pending",
		"identifiers": []any{map[string]any{"type": "dns", "value": "example.com"}},
	})
}

func TestDeactivateAccountErrors(t *testing.T) {
	t.Run("transport error", func(t *testing.T) {
		srv := closedFixtureServer(t)
		c := fixtureClient(srv)
		_, err := c.DeactivateAccount(context.Background(), fixtureAccount(t, srv))
		if err == nil {
			t.Error("DeactivateAccount succeeded against an unreachable server")
		}
	})

	t.Run("error response with problem document", func(t *testing.T) {
		srv := fixtures.NewServer(t)
		srv.Respond(http.MethodPost, "/acct/1", fixtures.Response{
			Status: http.StatusForbidden,
			Body:   testProblemJSON(t, ProblemTypeUnauthorized),
		})
		c := fixtureClient(srv)
		_, err := c.DeactivateAccount(context.Background(), fixtureAccount(t, srv))
		requireProblemError(t, err, ProblemTypeUnauthorized)
	})

	t.Run("invalid body", func(t *testing.T) {
		srv := fixtures.NewServer(t)
		srv.Respond(http.MethodPost, "/acct/1", fixtures.Response{
			Status: http.StatusOK,
			Body:   []byte("not json"),
		})
		c := fixtureClient(srv)
		_, err := c.DeactivateAccount(context.Background(), fixtureAccount(t, srv))
		if err == nil {
			t.Error("DeactivateAccount accepted a malformed body")
		}
	})

	t.Run("unexpected success status", func(t *testing.T) {
		srv := fixtures.NewServer(t)
		srv.Respond(http.MethodPost, "/acct/1", fixtures.Response{
			Status: http.StatusCreated,
			Body:   fixtures.JSON(t, map[string]any{"status": "deactivated"}),
		})
		c := fixtureClient(srv)
		_, err := c.DeactivateAccount(context.Background(), fixtureAccount(t, srv))
		requireErrorContaining(t, err, "unexpected status")
	})
}

func TestUpdateAccountContactErrors(t *testing.T) {
	t.Run("transport error", func(t *testing.T) {
		srv := closedFixtureServer(t)
		c := fixtureClient(srv)
		_, err := c.UpdateAccountContact(context.Background(), fixtureAccount(t, srv), []string{"mailto:test@example.com"})
		if err == nil {
			t.Error("UpdateAccountContact succeeded against an unreachable server")
		}
	})

	t.Run("error response with problem document", func(t *testing.T) {
		srv := fixtures.NewServer(t)
		srv.Respond(http.MethodPost, "/acct/1", fixtures.Response{
			Status: http.StatusForbidden,
			Body:   testProblemJSON(t, ProblemTypeUnauthorized),
		})
		c := fixtureClient(srv)
		_, err := c.UpdateAccountContact(context.Background(), fixtureAccount(t, srv), []string{"mailto:test@example.com"})
		requireProblemError(t, err, ProblemTypeUnauthorized)
	})

	t.Run("invalid body", func(t *testing.T) {
		srv := fixtures.NewServer(t)
		srv.Respond(http.MethodPost, "/acct/1", fixtures.Response{
			Status: http.StatusOK,
			Body:   []byte("not json"),
		})
		c := fixtureClient(srv)
		_, err := c.UpdateAccountContact(context.Background(), fixtureAccount(t, srv), []string{"mailto:test@example.com"})
		if err == nil {
			t.Error("UpdateAccountContact accepted a malformed body")
		}
	})

	t.Run("unexpected success status", func(t *testing.T) {
		srv := fixtures.NewServer(t)
		srv.Respond(http.MethodPost, "/acct/1", fixtures.Response{
			Status: http.StatusCreated,
			Body:   fixtures.JSON(t, map[string]any{"status": "valid"}),
		})
		c := fixtureClient(srv)
		_, err := c.UpdateAccountContact(context.Background(), fixtureAccount(t, srv), []string{"mailto:test@example.com"})
		requireErrorContaining(t, err, "unexpected status")
	})
}

func TestUpdateAccountKeyErrors(t *testing.T) {
	t.Run("transport error", func(t *testing.T) {
		srv := closedFixtureServer(t)
		c := fixtureClient(srv)
		_, err := c.UpdateAccountKey(context.Background(), fixtureAccount(t, srv), fixtureKey(t))
		if err == nil {
			t.Error("UpdateAccountKey succeeded against an unreachable server")
		}
	})

	t.Run("error response with problem document", func(t *testing.T) {
		srv := fixtures.NewServer(t)
		srv.Respond(http.MethodPost, "/keyChange", fixtures.Response{
			Status: http.StatusForbidden,
			Body:   testProblemJSON(t, ProblemTypeUnauthorized),
		})
		c := fixtureClient(srv)
		_, err := c.UpdateAccountKey(context.Background(), fixtureAccount(t, srv), fixtureKey(t))
		requireProblemError(t, err, ProblemTypeUnauthorized)
	})

	t.Run("unexpected success status", func(t *testing.T) {
		srv := fixtures.NewServer(t)
		srv.Respond(http.MethodPost, "/keyChange", fixtures.Response{
			Status: http.StatusCreated,
		})
		c := fixtureClient(srv)
		_, err := c.UpdateAccountKey(context.Background(), fixtureAccount(t, srv), fixtureKey(t))
		requireErrorContaining(t, err, "unexpected status")
	})
}

func TestNewOrderErrors(t *testing.T) {
	t.Run("transport error", func(t *testing.T) {
		srv := closedFixtureServer(t)
		c := fixtureClient(srv)
		_, err := c.newOrder(context.Background(), fixtureAccount(t, srv), []string{"example.com"}, OrderCfg{})
		if err == nil {
			t.Error("newOrder succeeded against an unreachable server")
		}
	})

	t.Run("error response with problem document", func(t *testing.T) {
		srv := fixtures.NewServer(t)
		srv.Respond(http.MethodPost, "/newOrder", fixtures.Response{
			Status: http.StatusForbidden,
			Body:   testProblemJSON(t, ProblemTypeUnauthorized),
		})
		c := fixtureClient(srv)
		_, err := c.newOrder(context.Background(), fixtureAccount(t, srv), []string{"example.com"}, OrderCfg{})
		requireProblemError(t, err, ProblemTypeUnauthorized)
	})

	t.Run("invalid body", func(t *testing.T) {
		srv := fixtures.NewServer(t)
		srv.Respond(http.MethodPost, "/newOrder", fixtures.Response{
			Status: http.StatusCreated,
			Header: http.Header{"Location": []string{srv.Endpoint("order/1")}},
			Body:   []byte("not json"),
		})
		c := fixtureClient(srv)
		_, err := c.newOrder(context.Background(), fixtureAccount(t, srv), []string{"example.com"}, OrderCfg{})
		if err == nil {
			t.Error("newOrder accepted a malformed body")
		}
	})

	t.Run("missing order location", func(t *testing.T) {
		srv := fixtures.NewServer(t)
		srv.Respond(http.MethodPost, "/newOrder", fixtures.Response{
			Status: http.StatusCreated,
			Body:   fixtureOrderBody(t),
		})
		c := fixtureClient(srv)
		_, err := c.newOrder(context.Background(), fixtureAccount(t, srv), []string{"example.com"}, OrderCfg{})
		requireErrorContaining(t, err, "no account location")
	})

	t.Run("unexpected success status", func(t *testing.T) {
		srv := fixtures.NewServer(t)
		srv.Respond(http.MethodPost, "/newOrder", fixtures.Response{
			Status: http.StatusOK,
			Header: http.Header{"Location": []string{srv.Endpoint("order/1")}},
			Body:   fixtureOrderBody(t),
		})
		c := fixtureClient(srv)
		_, err := c.newOrder(context.Background(), fixtureAccount(t, srv), []string{"example.com"}, OrderCfg{})
		requireErrorContaining(t, err, "unexpected status")
	})
}

func fixtureChallengeBody(t *testing.T, url string) []byte {
	t.Helper()
	return fixtures.JSON(t, map[string]any{
		"type":   "dns-01",
		"url":    url,
		"status": "pending",
		"token":  "test-token",
	})
}

func TestFetchUnmarshalAuthzErrors(t *testing.T) {
	t.Run("transport error", func(t *testing.T) {
		srv := closedFixtureServer(t)
		key := fixtureKey(t)
		c := fixtureClient(srv)
		var out authz
		err := c.fetchUnmarshalAuthz(context.Background(), srv.Endpoint("authz/1"), "acct/1", key.es256Key, &out)
		if err == nil {
			t.Error("fetchUnmarshalAuthz succeeded against an unreachable server")
		}
	})

	t.Run("error response with problem document", func(t *testing.T) {
		srv := fixtures.NewServer(t)
		srv.Respond(http.MethodPost, "/authz/1", fixtures.Response{
			Status: http.StatusForbidden,
			Body:   testProblemJSON(t, ProblemTypeUnauthorized),
		})
		key := fixtureKey(t)
		c := fixtureClient(srv)
		var out authz
		err := c.fetchUnmarshalAuthz(context.Background(), srv.Endpoint("authz/1"), "acct/1", key.es256Key, &out)
		requireProblemError(t, err, ProblemTypeUnauthorized)
	})

	t.Run("invalid body", func(t *testing.T) {
		srv := fixtures.NewServer(t)
		srv.Respond(http.MethodPost, "/authz/1", fixtures.Response{
			Status: http.StatusOK,
			Body:   []byte("not json"),
		})
		key := fixtureKey(t)
		c := fixtureClient(srv)
		var out authz
		err := c.fetchUnmarshalAuthz(context.Background(), srv.Endpoint("authz/1"), "acct/1", key.es256Key, &out)
		if err == nil {
			t.Error("fetchUnmarshalAuthz accepted a malformed body")
		}
	})

	t.Run("unexpected success status", func(t *testing.T) {
		srv := fixtures.NewServer(t)
		srv.Respond(http.MethodPost, "/authz/1", fixtures.Response{
			Status: http.StatusAccepted,
			Body:   fixtureAuthzBody(t, "example.com", "valid"),
		})
		key := fixtureKey(t)
		c := fixtureClient(srv)
		var out authz
		err := c.fetchUnmarshalAuthz(context.Background(), srv.Endpoint("authz/1"), "acct/1", key.es256Key, &out)
		requireErrorContaining(t, err, "unexpected status")
	})
}

func TestFetchChallengeErrors(t *testing.T) {
	t.Run("transport error", func(t *testing.T) {
		srv := closedFixtureServer(t)
		key := fixtureKey(t)
		c := fixtureClient(srv)
		_, err := c.fetchChallenge(context.Background(), srv.Endpoint("chall/1"), "acct/1", key.es256Key, []byte(`{}`))
		if err == nil {
			t.Error("fetchChallenge succeeded against an unreachable server")
		}
	})

	t.Run("error response with problem document", func(t *testing.T) {
		srv := fixtures.NewServer(t)
		srv.Respond(http.MethodPost, "/chall/1", fixtures.Response{
			Status: http.StatusForbidden,
			Body:   testProblemJSON(t, ProblemTypeUnauthorized),
		})
		key := fixtureKey(t)
		c := fixtureClient(srv)
		_, err := c.fetchChallenge(context.Background(), srv.Endpoint("chall/1"), "acct/1", key.es256Key, []byte(`{}`))
		requireProblemError(t, err, ProblemTypeUnauthorized)
	})

	t.Run("invalid body", func(t *testing.T) {
		srv := fixtures.NewServer(t)
		srv.Respond(http.MethodPost, "/chall/1", fixtures.Response{
			Status: http.StatusOK,
			Body:   []byte("not json"),
		})
		key := fixtureKey(t)
		c := fixtureClient(srv)
		_, err := c.fetchChallenge(context.Background(), srv.Endpoint("chall/1"), "acct/1", key.es256Key, []byte(`{}`))
		if err == nil {
			t.Error("fetchChallenge accepted a malformed body")
		}
	})

	t.Run("unexpected success status", func(t *testing.T) {
		srv := fixtures.NewServer(t)
		srv.Respond(http.MethodPost, "/chall/1", fixtures.Response{
			Status: http.StatusAccepted,
			Body:   fixtureChallengeBody(t, srv.Endpoint("chall/1")),
		})
		key := fixtureKey(t)
		c := fixtureClient(srv)
		_, err := c.fetchChallenge(context.Background(), srv.Endpoint("chall/1"), "acct/1", key.es256Key, []byte(`{}`))
		requireErrorContaining(t, err, "unexpected status")
	})
}

func TestChallengeFetchHelpersErrors(t *testing.T) {
	t.Run("fetchRawChallenge problem document", func(t *testing.T) {
		srv := fixtures.NewServer(t)
		srv.Respond(http.MethodPost, "/chall/1", fixtures.Response{
			Status: http.StatusForbidden,
			Body:   testProblemJSON(t, ProblemTypeUnauthorized),
		})
		key := fixtureKey(t)
		c := fixtureClient(srv)
		_, err := c.fetchRawChallenge(context.Background(), srv.Endpoint("chall/1"), "acct/1", key.es256Key)
		requireProblemError(t, err, ProblemTypeUnauthorized)
	})

	t.Run("acceptChallenge problem document", func(t *testing.T) {
		srv := fixtures.NewServer(t)
		srv.Respond(http.MethodPost, "/chall/1", fixtures.Response{
			Status: http.StatusForbidden,
			Body:   testProblemJSON(t, ProblemTypeUnauthorized),
		})
		key := fixtureKey(t)
		c := fixtureClient(srv)
		_, err := c.acceptChallenge(context.Background(), srv.Endpoint("chall/1"), "acct/1", key.es256Key)
		requireProblemError(t, err, ProblemTypeUnauthorized)
	})
}

func TestFetchAuthzErrors(t *testing.T) {
	t.Run("transport error", func(t *testing.T) {
		srv := closedFixtureServer(t)
		key := fixtureKey(t)
		c := fixtureClient(srv)
		out, err := c.fetchAuthz(context.Background(), []string{srv.Endpoint("authz/1")}, "acct/1", key.es256Key)
		if err == nil {
			t.Error("fetchAuthz succeeded against an unreachable server")
		}
		if out != nil {
			t.Errorf("authorizations = %+v, want nil on error", out)
		}
	})

	t.Run("error response with problem document", func(t *testing.T) {
		srv := fixtures.NewServer(t)
		srv.Respond(http.MethodPost, "/authz/1", fixtures.Response{
			Status: http.StatusOK,
			Body:   fixtureAuthzBody(t, "one.example.com", "valid"),
		})
		srv.Respond(http.MethodPost, "/authz/2", fixtures.Response{
			Status: http.StatusForbidden,
			Body:   testProblemJSON(t, ProblemTypeUnauthorized),
		})
		key := fixtureKey(t)
		c := fixtureClient(srv)
		urls := []string{srv.Endpoint("authz/1"), srv.Endpoint("authz/2")}
		out, err := c.fetchAuthz(context.Background(), urls, "acct/1", key.es256Key)
		requireProblemError(t, err, ProblemTypeUnauthorized)
		if out != nil {
			t.Errorf("authorizations = %+v, want nil on error", out)
		}
	})

	t.Run("invalid body", func(t *testing.T) {
		srv := fixtures.NewServer(t)
		srv.Respond(http.MethodPost, "/authz/1", fixtures.Response{
			Status: http.StatusOK,
			Body:   fixtureAuthzBody(t, "one.example.com", "valid"),
		})
		srv.Respond(http.MethodPost, "/authz/2", fixtures.Response{
			Status: http.StatusOK,
			Body:   []byte("not json"),
		})
		key := fixtureKey(t)
		c := fixtureClient(srv)
		urls := []string{srv.Endpoint("authz/1"), srv.Endpoint("authz/2")}
		out, err := c.fetchAuthz(context.Background(), urls, "acct/1", key.es256Key)
		if err == nil {
			t.Error("fetchAuthz accepted a malformed body")
		}
		if out != nil {
			t.Errorf("authorizations = %+v, want nil on error", out)
		}
	})

	t.Run("unexpected success status", func(t *testing.T) {
		srv := fixtures.NewServer(t)
		srv.Respond(http.MethodPost, "/authz/1", fixtures.Response{
			Status: http.StatusOK,
			Body:   fixtureAuthzBody(t, "one.example.com", "valid"),
		})
		srv.Respond(http.MethodPost, "/authz/2", fixtures.Response{
			Status: http.StatusAccepted,
			Body:   fixtureAuthzBody(t, "two.example.com", "valid"),
		})
		key := fixtureKey(t)
		c := fixtureClient(srv)
		urls := []string{srv.Endpoint("authz/1"), srv.Endpoint("authz/2")}
		out, err := c.fetchAuthz(context.Background(), urls, "acct/1", key.es256Key)
		requireErrorContaining(t, err, "unexpected status")
		if out != nil {
			t.Errorf("authorizations = %+v, want nil on error", out)
		}
	})
}
