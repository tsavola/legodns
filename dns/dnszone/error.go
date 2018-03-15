// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dnszone

import (
	"net"
)

const (
	// Try to be informative without being misleading in an unexpected context.
	resolver = "acmedns/dns/dnszone"
)

type existenceError struct {
	net.DNSError
}

func (*existenceError) NotExist() bool {
	return true
}

func newZoneError(name string) error {
	return &existenceError{
		DNSError: net.DNSError{
			Err:    "DNS zone is unknown",
			Name:   name,
			Server: resolver,
		},
	}
}

func newNodeError(name string) error {
	return &existenceError{
		DNSError: net.DNSError{
			Err:    "Node not found in DNS zone",
			Name:   name,
			Server: resolver,
		},
	}
}
