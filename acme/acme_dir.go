package acme

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
