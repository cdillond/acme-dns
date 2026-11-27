package acme

import "testing"

func TestNewResolverWithNameServer(t *testing.T) {
	r := NewResolverWithNameServer("1.1.1.1:53")
	if r == nil {
		t.Fatal("NewResolverWithNameServer returned nil")
	}
	if !r.PreferGo {
		t.Fatal("PreferGo is false")
	}
	if r.Dial == nil {
		t.Fatal("Dial is nil")
	}
}
