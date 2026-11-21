// Package do implements an ACME DNS provider using the DigitalOcean godo SDK.
package do

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/digitalocean/godo"

	"go.ciaran.lol/acme-dns/acme"
)

const providerName = "digitalocean"

// domainsClient is the subset of godo's DomainsService used by Provider.
type domainsClient interface {
	CreateRecord(context.Context, string, *godo.DomainRecordEditRequest) (*godo.DomainRecord, *godo.Response, error)
	DeleteRecord(context.Context, string, int) (*godo.Response, error)
}

// Provider provisions ACME challenge TXT records in a DigitalOcean managed zone.
type Provider struct {
	client     domainsClient
	baseDomain string
}

// NewProvider returns a Provider that manages records in baseDomain.
func NewProvider(token, baseDomain string) *Provider {
	client := godo.NewFromToken(token)
	client.UserAgent = acme.UserAgent

	return &Provider{
		client:     client.Domains,
		baseDomain: normalizeDomain(baseDomain),
	}
}

// Provision creates the ACME challenge TXT record. The returned cleanup function
// deletes the same record.
func (p *Provider) Provision(ctx context.Context, record acme.TxtRecord) (acme.CleanupFunc, error) {
	var (
		log = logFromContext(ctx, record)
		req = godo.DomainRecordEditRequest{
			Type: "TXT",
			Data: record.Value,
			TTL:  int(record.TTL),
		}
		created *godo.DomainRecord
		id      int
		err     error
	)

	if err = p.validate(); err != nil {
		return nil, err
	}

	if req.Name, err = relativeRecordName(record.Name, p.baseDomain); err != nil {
		return nil, err
	}

	if log != nil {
		log.InfoContext(ctx, "provisioning dns record")
	}

	created, _, err = p.client.CreateRecord(ctx, p.baseDomain, &req)
	if err != nil {
		return nil, fmt.Errorf("digitalocean: create TXT record %q: %w", record.Name, err)
	}
	if created == nil || created.ID <= 0 {
		return nil, fmt.Errorf("digitalocean: create TXT record %q: no record ID returned", record.Name)
	}

	if log != nil {
		log.InfoContext(ctx, "provisioned dns record", "record_id", created.ID)
	}

	id = created.ID

	return func(cleanupCtx context.Context) error {
		return p.deprovision(cleanupCtx, id)
	}, nil
}

func (p *Provider) deprovision(ctx context.Context, recordID int) error {
	var (
		log    = logFromContext(ctx, acme.TxtRecord{})
		apiErr *godo.ErrorResponse
		err    error
	)

	if err = p.validate(); err != nil {
		return err
	}
	if recordID <= 0 {
		return fmt.Errorf("digitalocean: invalid record ID %d", recordID)
	}

	if log != nil {
		log.InfoContext(ctx, "deprovisioning dns record")
	}

	_, err = p.client.DeleteRecord(ctx, p.baseDomain, recordID)
	if err == nil {
		if log != nil {
			log.InfoContext(ctx, "deprovisioned dns record")
		}
		return nil
	}

	// A record that is already gone is treated as a successful cleanup.
	if errors.As(err, &apiErr) && apiErr.Response != nil && apiErr.Response.StatusCode == http.StatusNotFound {
		if log != nil {
			log.InfoContext(ctx, "dns record already deleted")
		}
		return nil
	}

	return fmt.Errorf("digitalocean: delete TXT record %d: %w", recordID, err)
}

func (p *Provider) validate() error {
	if p == nil || p.client == nil {
		return errors.New("digitalocean: provider is not initialized")
	}
	if p.baseDomain == "" {
		return errors.New("digitalocean: base domain is empty")
	}
	return nil
}

// relativeRecordName converts an ACME challenge FQDN into the relative name
// expected by the DigitalOcean API.
func relativeRecordName(fqdn, baseDomain string) (string, error) {
	fqdn = normalizeDomain(fqdn)

	if fqdn == "" {
		return "", errors.New("digitalocean: empty TXT record name")
	}

	if strings.EqualFold(fqdn, baseDomain) {
		return "@", nil
	}

	suffix := "." + baseDomain
	if len(fqdn) <= len(suffix) || !strings.EqualFold(fqdn[len(fqdn)-len(suffix):], suffix) {
		return "", fmt.Errorf("digitalocean: TXT record %q is not in managed domain %q", fqdn, baseDomain)
	}

	return fqdn[:len(fqdn)-len(suffix)], nil
}

func normalizeDomain(name string) string {
	return strings.TrimSuffix(strings.TrimSpace(name), ".")
}

func logFromContext(ctx context.Context, record acme.TxtRecord) *slog.Logger {
	log, _ := ctx.Value(acme.LogKey{}).(*slog.Logger)
	if log == nil {
		return nil
	}

	return log.With("provider", providerName, "record", record)
}
