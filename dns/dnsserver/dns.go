// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dnsserver

import (
	"github.com/tsavola/acmedns/dns"
)

// Resolver can dump host and zone records.  It must be instantaneous.
type Resolver interface {
	// ResolveResource copies a host's records.  It should return the zero
	// value if and only if the name doesn't fall into any known zone: unknown
	// node names in known zones should be returned without records.
	//
	// serial is the current serial number of the node's zone.  It is non-zero
	// for known zones, and zero if zone wasn't found.
	ResolveResource(hostname string) (match dns.Node, serial uint32)

	// TransferZone copies the contents of a domain.  The apex node must be
	// first, if present.
	//
	// serial is the current serial number of the zone.  It is non-zero if the
	// zone was found, and zero if not.
	TransferZone(domain string) (zone []dns.Node, serial uint32)
}
