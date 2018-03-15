acmedns implements ACME-based TLS certificate renewal (read: Let's Encrypt) via
a standalone DNS server.

The [acmedns/autocert](https://godoc.org/github.com/tsavola/acmedns/autocert)
package is modeled after
[golang.org/x/crypto/acme/autocert](https://godoc.org/golang.org/x/crypto/acme/autocert).
It needs a DNS backend to work.

The [acmedns/dns/dnsserver](https://godoc.org/github.com/tsavola/acmedns/dns/dnsserver)
package implements an simple, authoritative DNS server.

autocert and dnsserver can be combined in a single Go program using the
[acmedns/dns/dnszone](https://godoc.org/github.com/tsavola/acmedns/dns/dnszone)
package, which implements an in-memory DNS zone database.

The aforementioned packages can also be combined with custom components,
e.g. to implement certificate renewal via a remote DNS server (replacing direct
dnszone usage with RPC calls) or via a cloud DNS service.

This repository includes a modified copy of acme/autocert.  It is licensed
under the same terms as all other code in this repository, but it's copyright
is held by The Go Authors.
