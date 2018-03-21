// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/acme"
	acmeautocert "golang.org/x/crypto/acme/autocert"

	"github.com/tsavola/acmedns/autocert"
	"github.com/tsavola/acmedns/dns"
	"github.com/tsavola/acmedns/dns/dnsserver"
	"github.com/tsavola/acmedns/dns/dnszone"
)

const (
	minTTL = 1
	maxTTL = 24 * 60 * 60
)

func main() {
	if err := Main(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

func Main() (err error) {
	var (
		dtl       = 5 * time.Minute
		listen    = ":53"
		ns        = ""
		email     = ""
		domain    = "example.invalid."
		a         = ""
		aaaa      = ""
		apex      = false
		wildcard  = false
		acmeURL   = "https://acme-staging.api.letsencrypt.org/directory"
		acmeDir   = ""
		acmeRenew = time.Hour * 24 * 30
		acmeTOS   = false
		verbose   = false
	)

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [options] node...\n\nOptions:\n", os.Args[0])
		flag.PrintDefaults()
	}

	flag.StringVar(&listen, "l", listen, "listening address")
	flag.StringVar(&ns, "ns", ns, "name of this authoritative name server")
	flag.StringVar(&email, "email", email, "admin email address (required with -ns and/or -cert)")
	flag.StringVar(&domain, "domain", domain, "zone name")
	flag.StringVar(&a, "a", a, "IPv4 address")
	flag.StringVar(&aaaa, "aaaa", aaaa, "IPv6 address")
	flag.DurationVar(&dtl, "ttl", dtl, "TTL")
	flag.BoolVar(&apex, "apex", apex, "apex node")
	flag.BoolVar(&wildcard, "wildcard", wildcard, "wildcard node")
	flag.StringVar(&acmeURL, "acme-url", acmeURL, "directory API URL")
	flag.StringVar(&acmeDir, "acme-dir", acmeDir, "request certificate and cache it in this directory (requires -acme-tos and -apex)")
	flag.DurationVar(&acmeRenew, "acme-renew", acmeRenew, "renew certificate before expiration")
	flag.BoolVar(&acmeTOS, "acme-tos", acmeTOS, "accept certificate authority's terms of service")
	flag.BoolVar(&verbose, "v", verbose, "debug logging")
	flag.Parse()

	nodes := flag.Args()

	var (
		logFlags int
		logger   *log.Logger
	)
	if verbose {
		logFlags = log.Ldate | log.Lmicroseconds
		logger = log.New(os.Stderr, "", logFlags)
	}
	log.SetFlags(logFlags)

	var (
		mbox string
	)
	if ns != "" {
		mbox, err = dnsserver.EmailMbox(email)
		if err != nil {
			log.Fatal(err)
		}
	}

	config := &dnsserver.Config{
		Addr:     listen,
		ErrorLog: logger,
		DebugLog: logger,
		Ready:    make(chan struct{}),
		SOA: dnsserver.SOA{
			NS:   dnsserver.DotSuffix(ns),
			Mbox: mbox,
		},
	}

	ttl := uint32(dtl / time.Second)
	if ttl < minTTL || ttl > maxTTL {
		log.Fatalf("TTL value is out of bounds: %v", dtl)
	}

	rs := &dns.Records{
		Addr: dns.AddrRecord{
			TTL: ttl,
		},
	}
	if a != "" {
		rs.Addr.A = net.ParseIP(a)
	}
	if aaaa != "" {
		rs.Addr.AAAA = net.ParseIP(aaaa)
	}

	zone := &dnszone.Zone{
		Domain: dnsserver.DotSuffix(domain),
		Nodes:  make(map[string]*dns.Records),
	}
	if apex {
		zone.Nodes[dns.Apex] = rs
	}
	for _, node := range nodes {
		zone.Nodes[node] = rs
	}
	if wildcard {
		zone.Nodes[dns.Wildcard] = rs
	}

	zones := dnszone.Init(zone)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errors := make(chan error, 2)

	if acmeDir != "" {
		if !acmeTOS {
			log.Fatal("-acme-dir specified without -acme-tos")
		}
		if !apex {
			log.Fatal("-acme-dir specified without -apex")
		}

		go func() {
			var (
				err error
			)
			defer func() {
				errors <- err
			}()

			manager := &autocert.Manager{
				Prompt:      acme.AcceptTOS,
				Cache:       acmeautocert.DirCache(acmeDir),
				DNS:         zones,
				RenewBefore: acmeRenew,
				Client:      &acme.Client{DirectoryURL: acmeURL},
				Email:       email,
				DebugLog:    logger,
			}

			<-config.Ready

			_, err = manager.GetCertificate(&tls.ClientHelloInfo{
				ServerName: domain,
			})
		}()
	}

	go func() {
		errors <- dnsserver.Serve(ctx, zones, config)
	}()

	for err == nil {
		err = <-errors
	}
	return
}
