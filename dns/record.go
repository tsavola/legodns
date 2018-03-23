// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

import (
	"fmt"
	"net"
)

type RecordA IPRecord
type RecordNS StringRecord
type RecordTXT StringsRecord
type RecordAAAA IPRecord

func (r *RecordA) DeepCopy() RecordA {
	return RecordA((*IPRecord)(r).DeepCopy())
}

func (r *RecordNS) DeepCopy() RecordNS {
	return RecordNS((*StringRecord)(r).DeepCopy())
}

func (r *RecordTXT) DeepCopy() RecordTXT {
	return RecordTXT((*StringsRecord)(r).DeepCopy())
}

func (r *RecordAAAA) DeepCopy() RecordAAAA {
	return RecordAAAA((*IPRecord)(r).DeepCopy())
}

func DeepCopyRecord(x interface{}) interface{} {
	switch r := x.(type) {
	case RecordA:
		return r.DeepCopy()

	case RecordNS:
		return r.DeepCopy()

	case RecordTXT:
		return r.DeepCopy()

	case RecordAAAA:
		return r.DeepCopy()

	default:
		panic(fmt.Errorf("dns: not a record: %v", x))
	}
}

// Records contains Record*-type items (values, not pointers).  There must not
// be more than one item of a given type.
type Records []interface{}

func (source Records) DeepCopy() Records {
	target := make(Records, 0, len(source))
	for _, x := range source {
		target = append(target, DeepCopyRecord(x))
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
