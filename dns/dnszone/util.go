// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dnszone

import (
	"fmt"
	"math"
	"time"
)

const (
	SerialEpoch = 1500000000 // Unix time
)

// TimeSerial creates a time-based serial number.  It has 1-second
// granularity. It is only defined for dates roughly between 2017-07-15
// (SerialEpoch) and 2106-02-06 (32-bit unsigned integer wrap-around).
//
// Zone serial numbers are generated using this function during Init().  After
// that they are incremented at most once per second.
func TimeSerial(t time.Time) uint32 {
	n := t.Unix() - SerialEpoch
	if n <= 0 || n > math.MaxUint32 {
		panic(fmt.Errorf("Serial number out of bounds: %d", n))
	}
	return uint32(n)
}
