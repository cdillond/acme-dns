package acme

import (
	"context"
)

type CleanupFunc func(context.Context) error

// A Provider updates a DNS record.
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
