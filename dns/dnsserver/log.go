// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dnsserver

import (
	"log"
)

// Logger is a subset of log.Logger.
type Logger interface {
	Printf(fmt string, args ...interface{})
}

type defaultLogger struct{}

func (defaultLogger) Printf(fmt string, args ...interface{}) {
	log.Printf("dnsserver: "+fmt, args...)
}
