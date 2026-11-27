package acme

import (
	"context"
)

// A [CleanupFunc] is a callback returned by [Provider.Provision], which deprovisions
// the DNS record provisioned by [Provider.Provision].
type CleanupFunc func(context.Context) error

// A [Provider] updates a DNS record for a domain and returns a [CleanupFunc] callback that deprovisions the DNS record.
type Provider interface {
	Provision(context.Context, TXTRecord) (CleanupFunc, error)
}
