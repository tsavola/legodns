// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import "net"

type RecordType uint16

// Types of DNS records.  The values must match the standard ones.
const (
	TypeA    RecordType = 1
	TypeNS              = 2
	TypeTXT             = 16
	TypeAAAA            = 28
)

type Record interface {
	DeepCopy() Record
	Empty() bool
	Type() RecordType
}

type RecordA IPRecord
type RecordNS StringRecord
type RecordTXT StringsRecord
type RecordAAAA IPRecord

func (r RecordA) DeepCopy() Record    { return RecordA((*IPRecord)(&r).DeepCopy()) }
func (r RecordNS) DeepCopy() Record   { return RecordNS((*StringRecord)(&r).DeepCopy()) }
func (r RecordTXT) DeepCopy() Record  { return RecordTXT((*StringsRecord)(&r).DeepCopy()) }
func (r RecordAAAA) DeepCopy() Record { return RecordAAAA((*IPRecord)(&r).DeepCopy()) }

func (r RecordA) Empty() bool    { return len(r.Value) == 0 }
func (r RecordNS) Empty() bool   { return r.Value == "" }
func (r RecordTXT) Empty() bool  { return len(r.Values) == 0 }
func (r RecordAAAA) Empty() bool { return len(r.Value) == 0 }

func (RecordA) Type() RecordType    { return TypeA }
func (RecordNS) Type() RecordType   { return TypeNS }
func (RecordTXT) Type() RecordType  { return TypeTXT }
func (RecordAAAA) Type() RecordType { return TypeAAAA }

// Records contains Record*-type items (values, not pointers).  There must not
// be more than one item of a given type.
type Records []Record

func (source Records) DeepCopy() Records {
	target := make(Records, 0, len(source))
	for _, r := range source {
		target = append(target, r.DeepCopy())
	}
	return target
}

type IPRecord struct {
	Value net.IP
	TTL   uint32
}

func (r *IPRecord) DeepCopy() IPRecord {
	return IPRecord{
		Value: append(net.IP(nil), r.Value...),
		TTL:   r.TTL,
	}
}

type StringRecord struct {
	Value string
	TTL   uint32
}

func (r *StringRecord) DeepCopy() StringRecord {
	return *r
}

type StringsRecord struct {
	Values []string
	TTL    uint32
}

func (r *StringsRecord) DeepCopy() StringsRecord {
	return StringsRecord{
		Values: append([]string(nil), r.Values...),
		TTL:    r.TTL,
	}
}
