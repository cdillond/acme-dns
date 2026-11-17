package acme

import (
	"context"
)

type CleanupFunc func(context.Context) error

// A [Provider] updates a DNS record for a domain.
// If a [Client]'s [Client.Log] field is non-nil, it will pass the logger to the
// [Provider] via the [context.Context], keyed with an empty [LogKey], when calling
// [Provider.Provision] and the returned [CleanupFunc].
type Provider interface {
	Provision(context.Context, TxtRecord) (CleanupFunc, error)
}

type acmeDirectoryMeta struct {
	TermsOfService          string   `json:"termsOfService"`
	Website                 string   `json:"website"`
	CAAIdentities           []string `json:"caaIdentities"`
	ExternalAccountRequired bool     `json:"externalAccountRequired"`
}

type acmeDirectory struct {
	NewNonce   string            `json:"newNonce"`
	NewAccount string            `json:"newAccount"`
	NewOrder   string            `json:"newOrder"`
	NewAuthz   string            `json:"newAuthz"`
	RevokeCert string            `json:"revokeCert"`
	KeyChange  string            `json:"keyChange"`
	Meta       acmeDirectoryMeta `json:"meta"`
}
