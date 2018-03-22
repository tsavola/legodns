// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/*

Package acmedns and its subpackages implement automatic ACME-based TLS
certificate renewal (Let's Encrypt) via a standalone DNS server.  The purpose
is to support wildcard certificates, which requires DNS verification.

This top-level package provides some reusable primitives, built on
https://golang.org/x/crypto/acme.


Subpackages

The autocert subpackage is modeled after https://golang.org/x/crypto/acme/autocert.
It can obtain and renew TLS certificates behind the scenes, during the normal
operation of a TLS listener.  A DNS backend must be plugged in to help it
fulfill ACME's DNS challenges.

The dns/dnsserver subpackage implements a simple, authoritative DNS server.
It expects a zone database to be plugged in.

The dns/dnszone subpackage implements just such a zone container.  The
autocert, dnszone, and dnsserver subsystems can be combined to implement the
whole certificate renewal process in one Go program.

Those subsystems can also be combined with custom components, e.g. if the TLS
listener and DNS server need to run in different processes or hosts, or to use
a cloud DNS service.


DNS configuration

The idea is that there are fewer moving parts if the TLS server and its name
server are the same server (e.g. 192.0.2.0).  We just need some domain names:
one for the name server (example.net), and one for the TLS server with wildcard
needs (example.org).  One could also be a subdomain of the other, but that
would be messier to illustrate.

1. Zone ``example.net'' is hosted somewhere.

2. Name ``ns.example.net'' is configured with address 192.0.2.0.

3. A server program using acmedns is running at 192.0.2.0.

4. It configures dnsserver as ``ns.example.net''.

5. It configures dnszone ``example.org'' with address 192.0.2.0 for all names.

6. ``ns.example.net'' is registered as the primary name server of the ``example.org'' domain.

7. Some slave name server mirroring ``ns.example.net'' should be registered as
a secondary name server of the ``example.org'' domain (but the setup works also
without one).

No fancy cloud DNS provider API adapters, just good *ahem* old DNS protocol!

Steps 3, 4, and 5 as code:

	package main

	import (
		"context"
		"net"

		"github.com/tsavola/acmedns/dns"
		"github.com/tsavola/acmedns/dns/dnsserver"
		"github.com/tsavola/acmedns/dns/dnszone"
	)

	func main() {
		// Step 4
		config := &dnsserver.Config{
			SOA: dnsserver.SOA{
				NS:   "ns.example.net.",
				Mbox: "hostmaster.example.net.",
			},
		}

		// Step 5
		zones := dnszone.Init(&dnszone.Zone{
			Domain: "example.org.",
			Nodes: map[string]*dns.Records{
				dns.Wildcard: &dns.Records{
					Addr: dns.AddrRecord{
						A:   net.ParseIP("192.0.2.0"),
						TTL: 7200,
					},
				},
			},
		})

		// Step 3
		panic(dnsserver.Serve(context.Background(), zones, config))
	}

*/
package acmedns
