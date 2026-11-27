package acme

import (
	"encoding/json/v2"
	"testing"
)

func TestExternalAccountBindingUnmarshalJSONFrom(t *testing.T) {
	const raw = `{"protected":"abc","payload":"def","signature":"ghi"}`

	var eab ExternalAccountBinding
	if err := json.Unmarshal([]byte(raw), &eab); err != nil {
		t.Fatal(err)
	}
	if got := string(eab); got != raw {
		t.Errorf("EAB = %q, want %q", got, raw)
	}
}

func TestExternalAccountBindingUnmarshalJSONFromInvalidJSON(t *testing.T) {
	var eab ExternalAccountBinding
	if err := json.Unmarshal([]byte(`{"protected":`), &eab); err == nil {
		t.Error("invalid JSON was accepted as an external account binding")
	}
}
