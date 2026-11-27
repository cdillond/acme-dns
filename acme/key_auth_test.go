package acme

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func TestDNS01ChallengeValue(t *testing.T) {
	key, err := NewAccountKey()
	if err != nil {
		t.Fatal(err)
	}
	j, err := key.newJWK()
	if err != nil {
		t.Fatal(err)
	}
	thumbprint, err := j.appendThumbprint(nil)
	if err != nil {
		t.Fatal(err)
	}

	const token = "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA"
	wantKeyAuth := token + "." + base64.RawURLEncoding.EncodeToString(thumbprint)
	if got := string(newKeyAuth(token, key.es256Key)); got != wantKeyAuth {
		t.Errorf("key authorization = %q, want %q", got, wantKeyAuth)
	}

	digest := sha256.Sum256([]byte(wantKeyAuth))
	want := base64.RawURLEncoding.EncodeToString(digest[:])
	got := newDNS01Txt(token, key.es256Key)
	if got != want {
		t.Errorf("DNS-01 value = %q, want %q", got, want)
	}
	if other := newDNS01Txt("another-token", key.es256Key); other == got {
		t.Error("different tokens produced the same DNS-01 value")
	}
}
