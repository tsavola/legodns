// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dnsserver

import (
	"fmt"
	"strings"
)

// EmailMbox converts "admin@example.org" to "admin.example.org." etc.  It
// rejects "user.name@example.org" etc.  Empty string is passed through.
func EmailMbox(email string) (mbox string, err error) {
	if at := strings.Index(email, "@"); at >= 0 {
		if dot := strings.Index(email, "."); dot >= 0 && dot < at {
			err = fmt.Errorf("Mbox email address has '.' before '@': %s", email)
			return
		}
		mbox = strings.Replace(email, "@", ".", 1)
	} else {
		mbox = email
	}
	mbox = DotSuffix(mbox)
	return
}

// DotSuffix ensures that the string as a dot suffix, unless it is the empty
// string.
func DotSuffix(name string) string {
	if name != "" && !strings.HasSuffix(name, ".") {
		name += "."
	}
	return name
}
