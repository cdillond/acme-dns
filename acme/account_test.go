package acme

import (
	"encoding/json/v2"
	"strings"
	"testing"
)

func TestAccountStatusRoundTrip(t *testing.T) {
	cases := []struct {
		s    string
		want AccountStatus
	}{
		{"", accountStatusUnspecified},
		{"valid", AccountStatusValid},
		{"deactivated", AccountStatusDeactivated},
		{"revoked", AccountStatusRevoked},
	}
	for _, tc := range cases {
		if got := newAccountStatus(tc.s); got != tc.want {
			t.Errorf("newAccountStatus(%q) = %d, want %d", tc.s, got, tc.want)
		}
		if got := tc.want.String(); got != tc.s {
			t.Errorf("String() = %q, want %q", got, tc.s)
		}
		b, err := json.Marshal(&tc.want)
		if err != nil {
			t.Fatal(err)
		}
		var got AccountStatus
		if err = json.Unmarshal(b, &got); err != nil || got != tc.want {
			t.Errorf("round trip = %d, %v; want %d", got, err, tc.want)
		}
	}
	if got := newAccountStatus("bogus"); got != accountStatusUnknown || got.String() != "unknown" {
		t.Errorf("unknown status = %d/%q", got, got.String())
	}
}

func TestAccountStatusUnmarshalJSONFromReadError(t *testing.T) {
	var status AccountStatus
	if err := json.Unmarshal([]byte(`"`), &status); err == nil {
		t.Error("malformed JSON was accepted as an account status")
	}
}

func TestAccountStatusUnmarshalJSONFromRejectsNonString(t *testing.T) {
	var status AccountStatus
	err := json.Unmarshal([]byte(`123`), &status)
	if err == nil || !strings.Contains(err.Error(), "invalid order status serialisation: 123") {
		t.Fatalf("error = %v, want invalid non-string status error", err)
	}
}
