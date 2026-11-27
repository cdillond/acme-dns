package acme

import (
	"fmt"
	"testing"
)

func TestValidateNonce(t *testing.T) {
	for _, nonce := range []string{"a", "AZaz09-_", "abcXYZ123_-"} {
		if err := validateNonce(nonce); err != nil {
			t.Errorf("validateNonce(%q) = %v, want nil", nonce, err)
		}
	}
	for _, nonce := range []string{"", "with space", "has=padding", "plus+sign", "slash/sign"} {
		if err := validateNonce(nonce); err == nil {
			t.Errorf("validateNonce(%q) = nil, want error", nonce)
		}
	}
}

func TestNonceCacheFIFO(t *testing.T) {
	var n nonceCache
	if got := n.get(); got != "" {
		t.Fatalf("empty cache returned %q", got)
	}

	for i := range cacheSize {
		n.put(fmt.Sprintf("nonce-%d", i))
	}
	for i := range cacheSize {
		if got, want := n.get(), fmt.Sprintf("nonce-%d", i); got != want {
			t.Fatalf("get %d = %q, want %q", i, got, want)
		}
	}
	if got := n.get(); got != "" {
		t.Errorf("drained cache returned %q", got)
	}

	n.put("next-1")
	n.put("next-2")
	for _, want := range []string{"next-1", "next-2"} {
		if got := n.get(); got != want {
			t.Errorf("get = %q, want %q", got, want)
		}
	}
}

func TestNonceCacheWraparound(t *testing.T) {
	var n nonceCache
	total := cacheSize + 5
	for i := range total {
		n.put(fmt.Sprintf("nonce-%d", i))
	}

	// The oldest entries are discarded when the ring buffer fills up.
	for i := 5; i < total; i++ {
		if got, want := n.get(), fmt.Sprintf("nonce-%d", i); got != want {
			t.Fatalf("get = %q, want %q", got, want)
		}
	}
	if got := n.get(); got != "" {
		t.Errorf("drained cache returned %q", got)
	}
}
