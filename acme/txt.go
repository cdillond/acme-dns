package acme

const DefaultTTL = 60

type TxtRecord struct {
	TTL   uint16
	Name  string
	Value string
}
