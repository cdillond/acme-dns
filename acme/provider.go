package acme

import (
	"context"
)

// A [CleanupFunc] is a callback returned by [Provider.Provision], which deprovisions
// the DNS record provisioned by [Provider.Provision].
type CleanupFunc func(context.Context) error

// A [Provider] updates a DNS record for a domain and returns a [CleanupFunc] callback that deprovisions the DNS record.
type Provider interface {
	Provision(context.Context, TxtRecord) (CleanupFunc, error)
}

type ACMEDirectoryMeta struct {
	TermsOfService          string   `json:"termsOfService"`
	Website                 string   `json:"website"`
	CAAIdentities           []string `json:"caaIdentities"`
	ExternalAccountRequired bool     `json:"externalAccountRequired"`
}

type ACMEDirectory struct {
	NewNonce   string            `json:"newNonce"`
	NewAccount string            `json:"newAccount"`
	NewOrder   string            `json:"newOrder"`
	NewAuthz   string            `json:"newAuthz"`
	RevokeCert string            `json:"revokeCert"`
	KeyChange  string            `json:"keyChange"`
	Meta       ACMEDirectoryMeta `json:"meta"`
}
