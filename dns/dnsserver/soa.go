// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dnsserver

import (
	"errors"
)

const (
	defaultRefresh = 2 * 60 * 60
	defaultRetry   = 15 * 60
	defaultExpire  = 14 * 24 * 60 * 60
	defaultMinTTL  = 60 * 60
	defaultTTL     = 60 * 60
)

// SOA record.  Zero value implies no authority.  If NS is specified, Mbox is
// also required.
type SOA struct {
	NS   string
	Mbox string

	Refresh uint32 // Defaults to a reasonable value
	Retry   uint32 // Defaults to a reasonable value
	Expire  uint32 // Defaults to a reasonable value
	MinTTL  uint32 // Defaults to a reasonable value
	TTL     uint32 // Defaults to a reasonable value
}

func (soa *SOA) init() error {
	if soa.NS != "" {
		if soa.Mbox == "" {
			return errors.New("dnsserver: SOA.NS field specified without SOA.Mbox")
		}

		if soa.Refresh == 0 {
			soa.Refresh = defaultRefresh
		}
		if soa.Retry == 0 {
			soa.Retry = defaultRetry
		}
		if soa.Expire == 0 {
			soa.Expire = defaultExpire
		}
		if soa.MinTTL == 0 {
			soa.MinTTL = defaultMinTTL
		}
		if soa.TTL == 0 {
			soa.TTL = defaultTTL
		}
	}

	return nil
}

func (soa *SOA) authority() bool {
	return soa.NS != ""
}
