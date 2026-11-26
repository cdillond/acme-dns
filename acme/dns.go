package acme

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"slices"
	"strings"
	"time"
)

// DefaultTTL is the default time-to-live, in seconds, for provisioned TXT records.
const DefaultTTL = 60

// TXTRecord describes a DNS TXT record used for an ACME dns-01 challenge.
// Providers receive this value from [Provider.Provision] and should create the
// record exactly as specified.
type TXTRecord struct {
	// TTL is the requested time-to-live for the record, in seconds.
	TTL uint16

	// Name is the domain name at which the record should be provisioned, for
	// example "_acme-challenge.example.com". It is supplied without a trailing
	// root dot; providers that require zone-relative names should strip their
	// configured base domain. For wildcard identifiers, Name is the base domain
	// without the "*." prefix, and for internationalized identifiers it is the
	// A-label form supplied by the ACME server.
	Name string

	// Value is the exact TXT data required by the challenge. It is the base64url
	// encoding of the SHA-256 digest of the key authorization and should be
	// provisioned as a single TXT string.
	Value string
}

// NewResolverWithNameServer accepts the address of a nameserver (e.g. "1.1.1.1:53", "8.8.8.8:53", "ns1.digitalocean.com:53")
// and returns a [*net.Resolver] that dials the provided nameserver address when resolving a DNS query. If the address is in
// the form "hostname:port" instead of "ip:port", the default resolver is used to resolve the hostname of the nameserver.
func NewResolverWithNameServer(address string) *net.Resolver {
	dialer := new(net.Dialer)
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, address)
		},
	}
}

func confirmTXT(ctx context.Context, r *net.Resolver, record TXTRecord) (bool, error) {
	var (
		s   []string
		err error
		// Make the query absolute so the resolver does not apply search domains.
		qname = strings.TrimSuffix(record.Name, ".") + "."
	)

	if s, err = r.LookupTXT(ctx, qname); err != nil {
		return false, err
	}

	return slices.Contains(s, record.Value), nil
}

func pollForDNS(ctx context.Context, log *slog.Logger, r *net.Resolver, record TXTRecord, interval time.Duration) error {
	var (
		err       error
		dnsErr    *net.DNSError
		ok, found bool
	)

	if log != nil {
		log = log.With("record", record)
		log.InfoContext(ctx, "querying dns")
	}

	for {
		found, err = confirmTXT(ctx, r, record)

		switch {
		case !found && err == nil:
			if log != nil {
				log.WarnContext(ctx, "record not confirmed", "reason", "potential stale dns cache")
			}
		case err != nil:
			if log != nil {
				log.WarnContext(ctx, "record not confirmed", "err", err)
			}
			if dnsErr, ok = errors.AsType[*net.DNSError](err); ok {
				if dnsErr.IsNotFound || dnsErr.IsTemporary {
					break
				}
			}
			return err
		default:
			if log != nil {
				log.InfoContext(ctx, "record propagation confirmed")
			}
			return nil
		}

		select {
		case <-time.After(interval):
		case <-ctx.Done():
			return ctx.Err()
		}

	}

}
