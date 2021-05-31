package dnsprovider

type DnsProvider interface {
	CreateDnsTextEntry(zone string, name string, value string) error
}
