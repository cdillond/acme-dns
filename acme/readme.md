## About
Package acme is a minimal, opinionated, implementation of an [ACME client](https://datatracker.ietf.org/doc/html/rfc8555), intended to be light-weight, modular, and secure. It supports only the `dns-01` challenge type. Although it should work with all ACME servers, its main target is Let's Encrypt.

### Timeouts and Cancellation
During calls to `client.OrderCertificate`, the client polls certain endpoints until they return a terminal status. The interval between requests can be configured with `client.PollInterval`. To place a limit on how long the client retries requests, users should set a timeout on the context supplied to `client.OrderCertificate`. 

Any `CleanupFunc` that the client runs is executed with a timeout of 10 seconds, regardless of whether the parent context has been canceled. 

### Logging
If the client's `Logger` field is non-nil, it may write messages to the provided logger. To disable logging, simply configure the client to use a nil logger. When calling `Provider.Provision` and the `CleanupFunc` returned by such a call, the client's logger
is passed to the function via the `ctx` argument. Implementations of `Provider` can extract the logger from the context using the `ExtractLogger` function.

### DNS Resolution
Before accepting an ACME server's challenge, the client provisions the DNS records for an order and confirms that the records have propagated. By default, it completes this confirmation via recursive resolution using `net.Resolver` with `PreferGo` set to `true`. This works well in most cases, but on some platforms or with certain configurations, users may encounter timeouts caused by stale records cached by the system's DNS resolver. To fix this issue, instead use a custom `DNSConfirmationFunc`.

## Example
```go
package main

import (
	"context"
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

	logger.InfoContext(ctx, "account key created", "key", key.PrivateKey())

	account, data, err := c.RequestAccount(ctx, key, acme.AccountCfg{TermsOfServiceAgreed: true})
	if err != nil {
		logger.ErrorContext(ctx, err.Error())
		os.Exit(1)
	}

	logger.InfoContext(ctx, "account created", "account_id", account.ID, "data", data)

	orderCtx, cancel := context.WithTimeout(ctx, 1*time.Minute)
	defer cancel()

	cert, err := c.OrderCertificate(orderCtx, account, map[string]acme.Provider{
		"*.example.com": digitalocean.NewProvider(tok, "example.com"),
		"example.com":   digitalocean.NewProvider(tok, "example.com"),
	}, acme.OrderCfg{})
	if err != nil {
		logger.ErrorContext(ctx, err.Error())
		os.Exit(1)
	}

	logger.InfoContext(ctx, "order completed", "certificate", cert)
}

```