// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dnszone

import (
	"testing"
)

func TestExistenceError(t *testing.T) {
	type errorInterface interface {
		Temporary() bool
		Timeout() bool
		NotExist() bool
	}

	for _, x := range []error{
		newZoneError("example.net."),
		newNodeError("www.example.net."),
	} {
		if x.Error() == "" {
			t.Error(x)
		}

		y, ok := x.(errorInterface)
		if ok {
			if y.Temporary() {
				t.Error(y)
			}

			if y.Timeout() {
				t.Error(y)
			}

			if !y.NotExist() {
				t.Error(y)
			}
		} else {
			t.Error(x)
		}
	}
}
