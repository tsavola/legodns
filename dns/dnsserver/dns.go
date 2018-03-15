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
	ResolveResource(hostname string) dns.Node

	// TransferZone copies the contents of a domain.  The apex node must be
	// first, if present.
	TransferZone(domain string) []dns.Node
}
