// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dnszone

import (
	"context"
	"strings"
	"sync"

	"github.com/tsavola/acmedns/dns"
)

// Container implements acmedns.DNS, autocert.DNS, and dnsserver.Resolver.
type Container struct {
	sync.RWMutex
	Zones []*Zone
}

func Contain(zones ...*Zone) *Container {
	return &Container{
		Zones: zones,
	}
}

func (c *Container) ResolveResource(name string) (result dns.Node) {
	c.RLock()
	defer c.RUnlock()

	for _, z := range c.Zones {
		if node, ok := z.matchResource(name); ok {
			result.Name = node
			if rs := z.resolveNode(node); rs != nil {
				result.Records = rs.DeepCopy()
			}
			return
		}
	}

	return
}

func (c *Container) ResolveZone(ctx context.Context, hostname string) (domain string, err error) {
	c.RLock()
	defer c.RUnlock()

	var zoneFound bool

	for _, z := range c.Zones {
		if node, ok := z.matchResource(hostname); ok {
			zoneFound = true
			if z.resolveNode(node) != nil {
				domain = z.Domain
				return
			}
		}
	}

	if zoneFound {
		err = newNodeError(hostname)
	} else {
		err = newZoneError(hostname)
	}
	return
}

func (c *Container) TransferZone(name string) []dns.Node {
	c.RLock()
	defer c.RUnlock()

	for _, z := range c.Zones {
		if z.Domain == name {
			return z.transfer()
		}
	}

	return nil
}

func (c *Container) ModifyTXTRecord(ctx context.Context, zone, node string, values []string, ttl uint32) error {
	c.Lock()
	defer c.Unlock()

	for _, z := range c.Zones {
		if z.Domain == zone {
			z.ModifyTXTRecord(node, values, ttl)
			return nil
		}
	}

	return newZoneError(zone)
}

type Zone struct {
	Domain string
	Nodes  map[string]*dns.Records
}

func (z *Zone) matchResource(name string) (node string, ok bool) {
	switch {
	case z.Domain == name:
		node = dns.Apex
		ok = true

	case strings.HasSuffix(name, "."+z.Domain):
		prefix := name[:len(name)-1-len(z.Domain)]
		if !strings.Contains(prefix, ".") {
			node = prefix
			ok = true
		}
	}

	return
}

func (z *Zone) resolveNode(node string) (rs *dns.Records) {
	rs = z.Nodes[node]
	if rs == nil && node != dns.Apex { // wildcard doesn't apply to apex
		rs = z.Nodes[dns.Wildcard]
	}
	return
}

func (z *Zone) transfer() (results []dns.Node) {
	results = make([]dns.Node, 0, len(z.Nodes))

	if rs := z.Nodes[dns.Apex]; rs != nil {
		results = append(results, dns.Node{
			Name:    dns.Apex,
			Records: rs.DeepCopy(),
		})
	}

	for name, rs := range z.Nodes {
		if name != dns.Apex && name != dns.Wildcard {
			results = append(results, dns.Node{
				Name:    name,
				Records: rs.DeepCopy(),
			})
		}
	}

	if rs := z.Nodes[dns.Wildcard]; rs != nil {
		results = append(results, dns.Node{
			Name:    dns.Wildcard,
			Records: rs.DeepCopy(),
		})
	}

	return
}

func (z *Zone) ModifyTXTRecord(node string, values []string, ttl uint32) {
	if z.Nodes == nil {
		z.Nodes = make(map[string]*dns.Records)
	}

	rs := z.Nodes[node]
	if rs == nil {
		rs = new(dns.Records)
		z.Nodes[node] = rs
	}

	rs.TXT = dns.TextRecord{
		Values: values,
		TTL:    ttl,
	}
}
