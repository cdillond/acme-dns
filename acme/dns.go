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

const DefaultTTL = 60

type TXTRecord struct {
	TTL   uint16
	Name  string
	Value string
}

// ResolveWithNameServer accepts the address of a nameserver (e.g. "1.1.1.1:53", "8.8.8.8:53", "ns1.digitalocean.com:53")
// and returns a *net.Resolver that dials the provided nameserver address when resolving a DNS query.
func ResolveWithNameServer(address string) *net.Resolver {
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
		s     []string
		err   error
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
				log.InfoContext(ctx, "record not confirmed", "reason", "potential stale dns cache")
			}
		case err != nil:
			if log != nil {
				log.InfoContext(ctx, "record not confirmed", "err", err)
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
