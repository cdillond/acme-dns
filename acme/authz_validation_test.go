package acme

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"go.ciaran.lol/acme-dns/acme/internal/fixtures"
)

func TestHandlePendingOrderReportsAuthzFailures(t *testing.T) {
	key, err := NewAccountKey()
	if err != nil {
		t.Fatal(err)
	}

	srv := fixtures.NewServer(t)

	addAuthz := func(path, domain, status string) string {
		url := srv.Endpoint(path)
		srv.Respond(http.MethodPost, "/"+path, fixtures.Response{
			Status: http.StatusOK,
			Header: http.Header{"Replay-Nonce": []string{"nonce-2"}},
			Body: fixtures.JSON(t, map[string]any{
				"identifier": map[string]any{"type": "dns", "value": domain},
				"status":     status,
			}),
		})
		return url
	}

	one := addAuthz("authz/1", "one.example.com", "invalid")

	// Delay the valid authorization so it is still in flight when the invalid
	// one fails and cancels its siblings.
	two := srv.Endpoint("authz/2")
	srv.Handle(http.MethodPost, "/authz/2", func(*http.Request) fixtures.Response {
		time.Sleep(100 * time.Millisecond)
		return fixtures.Response{
			Status: http.StatusOK,
			Header: http.Header{"Replay-Nonce": []string{"nonce-2"}},
			Body:   fixtureAuthzBody(t, "two.example.com", "valid"),
		}
	})

	c := Client{
		Dir:   ACMEDirectory{NewNonce: srv.Endpoint("newNonce")},
		cache: new(nonceCache),
	}

	o := order{Authorizations: []string{one, two}}
	err = c.handlePendingOrder(context.Background(), srv.Endpoint("acct/1"), key.es256Key, &o, nil, OrderCfg{})
	if err == nil {
		t.Fatal("handlePendingOrder accepted invalid authorizations")
	}
	if !errors.Is(err, ErrFailedAuthz) {
		t.Errorf("error = %v, want ErrFailedAuthz", err)
	}
	for _, want := range []string{one, "one.example.com", "invalid"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to contain %q", err, want)
		}
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %q, want the cancellation of the sibling authorization to be reported", err)
	}
	if !strings.Contains(err.Error(), two) {
		t.Errorf("error = %q, want it to identify the cancelled authorization %q", err, two)
	}
	if strings.Contains(err.Error(), "two.example.com") {
		t.Errorf("error = %q, want cancellation rather than a validation failure for the valid authorization", err)
	}
}
