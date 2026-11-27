package acme

import (
	"encoding/json/v2"
	"strings"
	"testing"
)

func TestChallengeStatusRoundTrip(t *testing.T) {
	cases := []struct {
		s    string
		want challengeStatus
	}{
		{"invalid", challengeStatusInvalid},
		{"pending", challengeStatusPending},
		{"processing", challengeStatusProcessing},
		{"valid", challengeStatusValid},
	}

	for _, tc := range cases {
		if got := newChallengeStatus(tc.s); got != tc.want {
			t.Errorf("newChallengeStatus(%q) = %d, want %d", tc.s, got, tc.want)
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

		var got challengeStatus
		if err = json.Unmarshal(b, &got); err != nil {
			t.Fatal(err)
		}
		if got != tc.want {
			t.Errorf("unmarshalled status = %d, want %d", got, tc.want)
		}
	}

	if got := newChallengeStatus("bogus"); got != challengeStatusUnknown {
		t.Errorf("newChallengeStatus(%q) = %d, want %d", "bogus", got, challengeStatusUnknown)
	}
	if got := challengeStatusUnknown.String(); got != "unknown" {
		t.Errorf("String() = %q, want %q", got, "unknown")
	}
}

func TestChallengeStatusUnmarshalJSONFromReadError(t *testing.T) {
	var status challengeStatus
	if err := json.Unmarshal([]byte(`"`), &status); err == nil {
		t.Error("malformed JSON was accepted as a challenge status")
	}
}

func TestChallengeStatusUnmarshalJSONFromRejectsNonString(t *testing.T) {
	var status challengeStatus
	err := json.Unmarshal([]byte(`123`), &status)
	if err == nil || !strings.Contains(err.Error(), "invalid order status serialisation: 123") {
		t.Fatalf("error = %v, want invalid non-string status error", err)
	}
}
