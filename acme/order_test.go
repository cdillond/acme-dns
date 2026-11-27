package acme

import (
	"encoding/json/v2"
	"strings"
	"testing"
)

func TestOrderStatusRoundTrip(t *testing.T) {
	cases := []struct {
		s    string
		want orderStatus
	}{
		{"invalid", orderStatusInvalid},
		{"pending", orderStatusPending},
		{"ready", orderStatusReady},
		{"processing", orderStatusProcessing},
		{"valid", orderStatusValid},
	}
	for _, tc := range cases {
		if got := newOrderStatus(tc.s); got != tc.want {
			t.Errorf("newOrderStatus(%q) = %d, want %d", tc.s, got, tc.want)
		}
		if got := tc.want.String(); got != tc.s {
			t.Errorf("String() = %q, want %q", got, tc.s)
		}
		b, err := json.Marshal(&tc.want)
		if err != nil {
			t.Fatal(err)
		}
		if want := `"` + tc.s + `"`; string(b) != want {
			t.Errorf("JSON = %q, want %q", b, want)
		}
		var got orderStatus
		if err = json.Unmarshal(b, &got); err != nil || got != tc.want {
			t.Errorf("round trip = %d, %v; want %d", got, err, tc.want)
		}
	}
	if got := newOrderStatus("bogus"); got != orderStatusUnknown || got.String() != "unknown" {
		t.Errorf("unknown status = %d/%q", got, got.String())
	}
}

func TestFilterChallengesFindsDNS01(t *testing.T) {
	src := []challenge{
		{Type: "http-01", Token: "http"},
		{Type: "dns-01", Token: "dns"},
	}
	got := pickDNSChallenge(src)
	if got == nil {
		t.Fatal("pickDNSChallenge returned nil")
	}
	if got.Type != "dns-01" || got.Token != "dns" {
		t.Fatalf("challenge = %+v, want dns-01 challenge", got)
	}
	if pickDNSChallenge([]challenge{{Type: "http-01"}}) != nil {
		t.Fatal("pickDNSChallenge returned a challenge when no dns-01 was present")
	}
}

func TestOrderStatusUnmarshalJSONFromReadError(t *testing.T) {
	var status orderStatus
	if err := json.Unmarshal([]byte(`"`), &status); err == nil {
		t.Error("malformed JSON was accepted as an order status")
	}
}

func TestOrderStatusUnmarshalJSONFromRejectsNonString(t *testing.T) {
	var status orderStatus
	err := json.Unmarshal([]byte(`123`), &status)
	if err == nil || !strings.Contains(err.Error(), "invalid order status serialisation: 123") {
		t.Fatalf("error = %v, want invalid non-string status error", err)
	}
}
