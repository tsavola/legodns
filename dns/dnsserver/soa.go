// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dnsserver

import (
	"errors"
)

const (
	soaDefaultSerial  = 1
	soaDefaultRefresh = 2 * 60 * 60
	soaDefaultRetry   = 15 * 60
	soaDefaultExpire  = 14 * 24 * 60 * 60
	soaDefaultMinTTL  = 1
	soaDefaultTTL     = 60 * 60
)

// SOA record.  Zero value implies no authority.  If NS is specified, Mbox is
// also required.
type SOA struct {
	NS      string
	Mbox    string
	Serial  uint32 // Defaults to 1
	Refresh uint32 // Defaults to a reasonable value
	Retry   uint32 // Defaults to a reasonable value
	Expire  uint32 // Defaults to a reasonable value
	MinTTL  uint32 // Defaults to a very small value
	TTL     uint32 // Defaults to a reasonable value
}

func (soa *SOA) init() error {
	if soa.NS != "" {
		if soa.Mbox == "" {
			return errors.New("dnsserver: SOA.NS field specified without SOA.Mbox")
		}

		if soa.Serial == 0 {
			soa.Serial = soaDefaultSerial
		}
		if soa.Refresh == 0 {
			soa.Refresh = soaDefaultRefresh
		}
		if soa.Retry == 0 {
			soa.Retry = soaDefaultRetry
		}
		if soa.Expire == 0 {
			soa.Expire = soaDefaultExpire
		}
		if soa.MinTTL == 0 {
			soa.MinTTL = soaDefaultMinTTL
		}
		if soa.TTL == 0 {
			soa.TTL = soaDefaultTTL
		}
	}

	return nil
}
