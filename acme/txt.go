package acme

const DefaultTTL = 300

type TxtRecord struct {
	TTL   uint16
	Name  string
	Value string
}
