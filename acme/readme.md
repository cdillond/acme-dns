Package acme is a minimal, opinionated, implementation of an [ACME client](https://datatracker.ietf.org/doc/html/rfc8555), intended to be light-weight, modular, and secure. It supports only the `dns-01` challenge type.


## Example
```go
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"go.ciaran.lol/acme-dns/acme"
	"go.ciaran.lol/acme-dns/providers/digitalocean"
)

func main() {
	ctx := context.Background()
	logger := slog.Default()

	tok := os.Getenv("DO_TOKEN")
	if tok == "" {
		logger.ErrorContext(ctx, "no token")
		os.Exit(1)
	}

	c, err := acme.NewClient(ctx, acme.LetsEncryptStagingURL, logger)
	if err != nil {
		logger.ErrorContext(ctx, err.Error())
		os.Exit(1)
	}

	key, err := acme.NewAccountKey()
	if err != nil {
		logger.ErrorContext(ctx, err.Error())
		os.Exit(1)
	}

	fmt.Println(key.PrivateKey())

	account, data, err := c.RequestAccount(ctx, key, acme.AccountCfg{TermsOfServiceAgreed: true})
	if err != nil {
		logger.ErrorContext(ctx, err.Error())
		os.Exit(1)
	}

	cert, err := c.OrderCertificate(ctx, account, map[string]acme.Provider{
		"*.example.com": digitalocean.NewProvider(tok, "example.com"),
		"example.com":   digitalocean.NewProvider(tok, "example.com"),
	}, acme.OrderCfg{})
	if err != nil {
		logger.ErrorContext(ctx, err.Error())
		os.Exit(1)
	}

	fmt.Println(cert)
}


```