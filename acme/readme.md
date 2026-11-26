[![Go Reference](https://pkg.go.dev/badge/go.ciaran.lol/acme-dns/acme.svg)](https://pkg.go.dev/go.ciaran.lol/acme-dns/acme)


## About
Package acme is a minimal, opinionated, implementation of an [ACME client](https://datatracker.ietf.org/doc/html/rfc8555), intended to be light-weight, modular, and secure. It supports only the `dns-01` challenge type. Although it should work with all ACME servers, its primary target is Let's Encrypt.

### Timeouts and Cancellation
During calls to `Client.OrderCertificate`, the client polls certain endpoints until they return a terminal status. The interval between requests can be configured with `Client.PollInterval`. To place a limit on how long the client retries requests, users should set a timeout on the context supplied to `Client.OrderCertificate`. 

Any `CleanupFunc` that the client runs is executed with a timeout of 10 seconds, regardless of whether the parent context has been canceled. 

### Logging
If the client's `Log` field is non-nil, it may write messages to the provided logger. To disable logging, simply configure the client to use a nil logger. When calling `Provider.Provision` and the `CleanupFunc` returned by such a call, the client's logger is passed to the function via the `ctx` argument. Implementations of `Provider` can extract the logger from the context using the `ExtractLogger` function.

### DNS Resolution Pitfalls
Before accepting an ACME server's challenge, the client provisions the DNS records for an order and confirms that the records have propagated. By default, it completes this confirmation via recursive resolution using `net.Resolver` with `PreferGo` set to `true`, but users who wish to use a different resolver can configure this behaviour by providing a custom value for the `OrderCfg.Resolver` passed to `Client.OrderCertificate`. When requesting multiple certificates for a single domain in quick succession it is best to do so for only a single `Account`. Otherwise, the ACME server (and client) may encounter stale cached DNS records that cause the challenge to timeout or fail validation. That issue can be exacerbated if an `OrderCfg` has a long `RecordTTLSeconds` field.

### Account Management
An `Account` object has an `ID` and a `Key`. The `ID` is determined by the ACME server during account registration, and always takes the form of a URL. The `Key` is an `AccountKey` that contains an `*ecdsa.PrivateKey` supplied by the user, which is used for signing requests made to the server. The `Key` is also used to identify an existing account when calling `Client.RequestAccount`. That is, if an ACME server has an account with a public key that matches the public key derived from the supplied private key, it will return the existing account rather than create a new one. The `Client.RequestAccount` method is not idempotent: the server will not update an existing account to match the supplied `AccountCfg` details if they differ from the data stored by the server. To update account data, such as an `AccountKey` or account contact, use the appropriate `Client.UpdateAccount*` method. An account can be deactivated with `Client.DeactivateAccount`.

### Certificate Management
Certificates for a set of domains can be ordered via the `Client.OrderCertificate` method. The returned `Certificate` contains a chain of x509 certificates valid for all domains in the input set and the private key that corresponds to the public key of the leaf certificate. The leaf certificate is always `Certificate.Chain[0]` (or, for convenience, the output of `Certificate.Chain.Leaf`). When revoking a certificate, the leaf certificate is the only certificate that should be passed to `Client.RevokeCert`. The `Certificate.PrivateKey` field always contains a `crypto.PrivateKey` with the concrete type of `*ecdsa.PrivateKey` and a `Curve` equivalent to the one returned by `elliptic.P256`.

ACME does not provide a direct mechanism for certificate renewal. Instead, renewals are obtained in an identical manner to all other certificates:  
```
If the client wishes to obtain a renewed certificate, the client initiates a new order process to request one.
```
Users with an existing `Certificate` are advised to check if it meets the criteria for renewal by calling `ShouldRenew` before placing a new order.

## Example
```go
package main

import (
	"context"
	"log/slog"
	"os"
	"time"

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
