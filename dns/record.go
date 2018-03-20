// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"net"
)

type Records struct {
	Addr AddrRecord
	TXT  TextRecord
	NS   StringRecord
}

func (rs *Records) DeepCopy() Records {
	return Records{
		Addr: rs.Addr.DeepCopy(),
		TXT:  rs.TXT.DeepCopy(),
		NS:   rs.NS.DeepCopy(),
	}
}

type AddrRecord struct {
	A    net.IP
	AAAA net.IP
	TTL  uint32
}

func (r *AddrRecord) DeepCopy() AddrRecord {
	return AddrRecord{
		A:    append(net.IP(nil), r.A...),
		AAAA: append(net.IP(nil), r.AAAA...),
		TTL:  r.TTL,
	}
}

type TextRecord struct {
	Values []string
	TTL    uint32
}

func (r *TextRecord) DeepCopy() TextRecord {
	return TextRecord{
		Values: append([]string(nil), r.Values...),
		TTL:    r.TTL,
	}
}

type StringRecord struct {
	Value string
	TTL   uint32
}

func (r *StringRecord) DeepCopy() StringRecord {
	return *r
}
