// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dnsserver_test

import (
	"context"
	"net"
	"testing"

	dnsclient "github.com/miekg/dns"
	"github.com/tsavola/acmedns/dns"
	"github.com/tsavola/acmedns/dns/dnsserver"
	"github.com/tsavola/acmedns/dns/dnszone"
)

const (
	addr = "127.0.0.1:54311"
)

func TestServer(t *testing.T) {
	config := &dnsserver.Config{
		Addr:  addr,
		Ready: make(chan struct{}),
	}

	orgZone := &dnszone.Zone{
		Domain: "example.org.",
		Nodes: map[string]*dns.Records{
			dns.Apex: &dns.Records{
				Addr: dns.AddrRecord{
					A:    net.ParseIP("93.184.216.34"),
					AAAA: net.ParseIP("2606:2800:220:1:248:1893:25c8:1946"),
					TTL:  1,
				},
			},
		},
	}

	comZone := &dnszone.Zone{
		Domain: "example.com.",
	}

	zones := dnszone.Contain(orgZone, comZone)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	served := make(chan error, 1)

	go func() {
		defer close(served)
		served <- dnsserver.Serve(ctx, zones, config)
	}()

	<-config.Ready

	client := &dnsclient.Client{
		Net: "tcp",
	}

	for _, name := range []string{"_acme-challenge.example.org.", "example.org.", "www.example.com.", "www.example.net."} {
		for _, typ := range []uint16{dnsclient.TypeA, dnsclient.TypeAAAA, dnsclient.TypeTXT} {
			msg := new(dnsclient.Msg)
			msg.SetQuestion(name, typ)

			in, _, err := client.Exchange(msg, addr)
			if err != nil {
				t.Error(err)
			} else {
				t.Log(in)
			}

			err = zones.ModifyTXTRecord(ctx, "example.org.", "_acme-challenge", []string{"asdf"}, 1)
			if err != nil {
				t.Error(err)
			}
		}
	}

	cancel()

	if err := <-served; err != nil && err != context.Canceled {
		t.Fatal(err)
	}
}
