module go.ciaran.lol/acme-dns/providers/digitalocean

go 1.27.3

require (
	github.com/digitalocean/godo v1.244.0
	go.ciaran.lol/acme-dns/acme v0.0.10
)

require (
	github.com/google/go-querystring v1.1.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-retryablehttp v0.7.7 // indirect
	golang.org/x/oauth2 v0.38.0 // indirect
	golang.org/x/time v0.6.0 // indirect
)

replace go.ciaran.lol/acme-dns/acme => ../../acme
