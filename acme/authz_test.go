package acme

import (
	"encoding/json/v2"
	"strings"
	"testing"
)

func TestAuthzStatusRoundTrip(t *testing.T) {
	cases := []struct {
		s    string
		want authzStatus
	}{
		{"invalid", authzStatusInvalid},
		{"pending", authzStatusPending},
		{"valid", authzStatusValid},
		{"deactivated", authzStatusDeactivated},
		{"expired", authzStatusExpired},
		{"revoked", authzStatusRevoked},
	}
	for _, tc := range cases {
		if got := newAuthzStatus(tc.s); got != tc.want {
			t.Errorf("newAuthzStatus(%q) = %d, want %d", tc.s, got, tc.want)
		}
		if got := tc.want.String(); got != tc.s {
			t.Errorf("String() = %q, want %q", got, tc.s)
		}
		b, err := json.Marshal(&tc.want)
		if err != nil {
			t.Fatal(err)
		}
		var got authzStatus
		if err = json.Unmarshal(b, &got); err != nil || got != tc.want {
			t.Errorf("round trip = %d, %v; want %d", got, err, tc.want)
		}
	}
	if got := newAuthzStatus("bogus"); got != authzStatusUnknown || got.String() != "unknown" {
		t.Errorf("unknown status = %d/%q", got, got.String())
	}
}

func TestAuthzStatusUnmarshalJSONFromReadError(t *testing.T) {
	var status authzStatus
	if err := json.Unmarshal([]byte(`"`), &status); err == nil {
		t.Error("malformed JSON was accepted as an authorization status")
	}
}

func TestAuthzStatusUnmarshalJSONFromRejectsNonString(t *testing.T) {
	var status authzStatus
	err := json.Unmarshal([]byte(`123`), &status)
	if err == nil || !strings.Contains(err.Error(), "invalid order status serialisation: 123") {
		t.Fatalf("error = %v, want invalid non-string status error", err)
	}
}
