package acme

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
)

type csr struct {
	CSR string `json:"csr"`
}

func newCSR(key *ecdsa.PrivateKey, dnsNames []string) (csr, error) {

	der, err := x509.CreateCertificateRequest(
		rand.Reader,
		&x509.CertificateRequest{
			DNSNames: dnsNames,
		},
		key,
	)

	if err != nil {
		return csr{}, err
	}

	return csr{base64.RawURLEncoding.EncodeToString(der)}, nil
}
