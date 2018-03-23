// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package dnsserver implements a simple, authoritative DNS server.  It is
// built upon https://github.com/miekg/dns.
//
// See the top-level package for general documentation.
package dnsserver

import (
	"context"
	"net"
	"strings"

	"github.com/miekg/dns"
	naming "github.com/tsavola/acmedns/dns"
)

const (
	// Serial number used for negative answers.
	defaultSerial = 1
)

// Config of DNS server.
type Config struct {
	Addr  string // Defaults to ":dns"
	NoTCP bool
	NoUDP bool

	ErrorLog Logger // Defaults to log package's standard logger
	DebugLog Logger // Defaults to nothingness

	// If provided, this channel will be closed once all listeners are ready.
	Ready chan struct{}

	// If the NS field of SOA is set, the name server will be authoritative and
	// NS and SOA records are returned.
	SOA SOA
}

// Serve DNS requests for the duration of the context.  Resolver implementation
// effectively defines the zones.  Configuration is optional.
func Serve(ctx context.Context, resolver Resolver, serverConfig *Config) (err error) {
	var config Config

	if serverConfig != nil {
		config = *serverConfig
	}

	if config.ErrorLog == nil {
		config.ErrorLog = defaultLogger{}
	}

	err = config.SOA.init()
	if err != nil {
		return
	}

	handler := dns.HandlerFunc(func(w dns.ResponseWriter, m *dns.Msg) {
		handle(w, m, resolver, &config.SOA, config.ErrorLog, config.DebugLog)
	})

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errors := make(chan error, 4) // (tcp, udp) x (context, listener)

	if !config.NoTCP {
		var l net.Listener

		l, err = net.Listen("tcp", config.Addr)
		if err != nil {
			return
		}

		go func() {
			defer l.Close()
			<-ctx.Done()
			errors <- ctx.Err()
		}()

		go func() {
			errors <- dns.ActivateAndServe(l, nil, handler)
		}()
	}

	if !config.NoUDP {
		var pc net.PacketConn

		pc, err = net.ListenPacket("udp", config.Addr)
		if err != nil {
			return
		}

		go func() {
			defer pc.Close()
			<-ctx.Done()
			errors <- ctx.Err()
		}()

		go func() {
			errors <- dns.ActivateAndServe(nil, pc, handler)
		}()
	}

	if config.Ready != nil {
		close(config.Ready)
	}

	err = <-errors
	return
}

func handle(w dns.ResponseWriter, questMsg *dns.Msg, resolver Resolver, soa *SOA, errorLog, debugLog Logger) {
	defer func() {
		if x := recover(); x != nil {
			errorLog.Printf("panic: %v", x)
		}
	}()

	defer func() {
		if err := w.Close(); err != nil {
			errorLog.Printf("close: %v", err)
		}
	}()

	var replyMsg dns.Msg
	replyCode := dns.RcodeServerFailure

	defer func() {
		if debugLog != nil && replyCode != dns.RcodeSuccess {
			debugLog.Printf("dnsserver: %v %s", w.RemoteAddr(), dns.RcodeToString[replyCode])
		}

		if err := w.WriteMsg(replyMsg.SetRcode(questMsg, replyCode)); err != nil {
			errorLog.Printf("write: %v", err)
		}
	}()

	if len(questMsg.Question) != 1 {
		replyCode = dns.RcodeNotImplemented
		return
	}

	q := questMsg.Question[0]

	if q.Qclass != dns.ClassINET {
		replyCode = dns.RcodeNotImplemented
		return
	}

	if debugLog != nil {
		debugLog.Printf("dnsserver: %v %s %q", w.RemoteAddr(), dns.TypeToString[q.Qtype], q.Name)
	}

	replyMsg.Authoritative = soa.authority()

	var (
		serial  uint32
		nodes   []naming.Node
		hasApex bool
	)

	if transferReq(&q) {
		if soa.authority() {
			nodes, serial = resolver.TransferZone(strings.ToLower(q.Name))
			hasApex = true
		}
	} else {
		var (
			node string
			rs   naming.Records
		)

		node, rs, serial = resolver.ResolveRecords(strings.ToLower(q.Name), naming.RecordType(q.Qtype))
		if node != "" {
			nodes = []naming.Node{{Name: node, Records: rs}}
			hasApex = (node == naming.Apex)
		}
	}

	if nodes != nil {
		if hasApex && soa.authority() {
			if replyType(&q, dns.TypeSOA) {
				replyMsg.Answer = append(replyMsg.Answer, soaAnswer(&q, soa, serial))
			}

			if replyType(&q, dns.TypeNS) {
				replyMsg.Answer = append(replyMsg.Answer, &dns.NS{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeNS,
						Class:  dns.ClassINET,
						Ttl:    soa.TTL,
					},
					Ns: soa.NS,
				})
			}
		}

		for _, node := range nodes {
			var name string

			switch node.Name {
			case naming.Apex:
				name = q.Name

			case naming.Wildcard:
				name = "*." + q.Name

			default:
				if hasApex {
					name = node.Name + "." + q.Name
				} else {
					name = q.Name
				}
			}

			for _, x := range node.Records {
				switch t := x.Type(); t {
				case naming.TypeNS:
					if replyType(&q, dns.TypeNS) {
						r := x.(naming.RecordNS)
						replyMsg.Answer = append(replyMsg.Answer, &dns.NS{
							Hdr: dns.RR_Header{
								Name:   name,
								Rrtype: dns.TypeNS,
								Class:  dns.ClassINET,
								Ttl:    r.TTL,
							},
							Ns: r.Value,
						})
					}

				case naming.TypeA:
					if replyType(&q, dns.TypeA) {
						r := x.(naming.RecordA)
						replyMsg.Answer = append(replyMsg.Answer, &dns.A{
							Hdr: dns.RR_Header{
								Name:   name,
								Rrtype: dns.TypeA,
								Class:  dns.ClassINET,
								Ttl:    r.TTL,
							},
							A: r.Value,
						})
					}

				case naming.TypeAAAA:
					if replyType(&q, dns.TypeAAAA) {
						r := x.(naming.RecordAAAA)
						replyMsg.Answer = append(replyMsg.Answer, &dns.AAAA{
							Hdr: dns.RR_Header{
								Name:   name,
								Rrtype: dns.TypeAAAA,
								Class:  dns.ClassINET,
								Ttl:    r.TTL,
							},
							AAAA: r.Value,
						})
					}

				case naming.TypeTXT:
					if replyType(&q, dns.TypeTXT) {
						r := x.(naming.RecordTXT)
						replyMsg.Answer = append(replyMsg.Answer, &dns.TXT{
							Hdr: dns.RR_Header{
								Name:   name,
								Rrtype: dns.TypeTXT,
								Class:  dns.ClassINET,
								Ttl:    r.TTL,
							},
							Txt: r.Values,
						})
					}

				default:
					if debugLog != nil {
						debugLog.Printf("dnsserver: node %q has unknown record type: %v", name, t)
					}
				}
			}
		}

		if transferReq(&q) {
			// Zone transfer is concluded with repeated SOA record
			replyMsg.Answer = append(replyMsg.Answer, soaAnswer(&q, soa, serial))
		}

		replyCode = dns.RcodeSuccess
	} else {
		replyCode = dns.RcodeNameError
	}

	// RFC 2308, Section 3: SOA in Authority section for negative answers
	if negativeAnswer(&replyMsg, replyCode) && soa.authority() {
		replyMsg.Ns = append(replyMsg.Ns, soaAnswer(&q, soa, serial))
	}
}

// replyType returns true if records with recordType should be included in the
// reply message for the given question.
func replyType(q *dns.Question, recordType uint16) bool {
	switch q.Qtype {
	case dns.TypeAXFR, dns.TypeIXFR, dns.TypeANY, recordType:
		return true

	default:
		return false
	}
}

// transferReq returns true if question is some kind of zone transfer request.
func transferReq(q *dns.Question) bool {
	switch q.Qtype {
	case dns.TypeAXFR, dns.TypeIXFR:
		return true

	default:
		return false
	}
}

func negativeAnswer(replyMsg *dns.Msg, replyCode int) bool {
	return replyCode == dns.RcodeNameError || len(replyMsg.Answer) == 0
}

func soaAnswer(q *dns.Question, soa *SOA, serial uint32) *dns.SOA {
	if serial == 0 {
		serial = defaultSerial
	}

	return &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    soa.TTL,
		},
		Ns:      soa.NS,
		Mbox:    soa.Mbox,
		Serial:  serial,
		Refresh: soa.Refresh,
		Retry:   soa.Retry,
		Expire:  soa.Expire,
		Minttl:  soa.TTL,
	}
}
