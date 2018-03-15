// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dns

// Special node names.
const (
	Apex     = "@"
	Wildcard = "*"
)

// Node carries information about a host within a zone.
type Node struct {
	Name string // Empty name indicates nonexistent/unknown node
	Records
}
