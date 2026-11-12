package acme

type CADirURL string

const (
	CADirURLLetsEncryptStaging CADirURL = "https://acme-staging-v02.api.letsencrypt.org/directory"
	CADirURLLetsEncrypt        CADirURL = "https://acme-v02.api.letsencrypt.org/directory"
)
