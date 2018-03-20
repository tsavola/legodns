// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package dnsserver

import (
	"context"
	"net"
	"strings"

	"github.com/miekg/dns"
	naming "github.com/tsavola/acmedns/dns"
)

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
		hasApex bool
		nodes   []naming.Node
	)

	switch q.Qtype {
	case dns.TypeAXFR: // TODO: dns.TypeIXFR?
		hasApex = true
		if soa.authority() {
			nodes = resolver.TransferZone(strings.ToLower(q.Name))
		}

	default:
		if node := resolver.ResolveResource(strings.ToLower(q.Name)); node.Name != "" {
			hasApex = (node.Name == naming.Apex)
			nodes = []naming.Node{node}
		}
	}

	if nodes != nil {
		if hasApex && soa.authority() {
			if replyType(&q, dns.TypeSOA) {
				replyMsg.Answer = append(replyMsg.Answer, soaAnswer(&q, soa))
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

			if len(node.Addr.A) != 0 && replyType(&q, dns.TypeA) {
				replyMsg.Answer = append(replyMsg.Answer, &dns.A{
					Hdr: dns.RR_Header{
						Name:   name,
						Rrtype: dns.TypeA,
						Class:  dns.ClassINET,
						Ttl:    node.Addr.TTL,
					},
					A: node.Addr.A,
				})
			}

			if len(node.Addr.AAAA) != 0 && replyType(&q, dns.TypeAAAA) {
				replyMsg.Answer = append(replyMsg.Answer, &dns.AAAA{
					Hdr: dns.RR_Header{
						Name:   name,
						Rrtype: dns.TypeAAAA,
						Class:  dns.ClassINET,
						Ttl:    node.Addr.TTL,
					},
					AAAA: node.Addr.AAAA,
				})
			}

			if len(node.TXT.Values) != 0 && replyType(&q, dns.TypeTXT) {
				replyMsg.Answer = append(replyMsg.Answer, &dns.TXT{
					Hdr: dns.RR_Header{
						Name:   name,
						Rrtype: dns.TypeTXT,
						Class:  dns.ClassINET,
						Ttl:    node.TXT.TTL,
					},
					Txt: node.TXT.Values,
				})
			}
		}

		if q.Qtype == dns.TypeAXFR {
			// AXFR is concluded with repeated SOA record
			replyMsg.Answer = append(replyMsg.Answer, soaAnswer(&q, soa))
		}

		replyCode = dns.RcodeSuccess
	} else {
		replyCode = dns.RcodeNameError
	}

	// RFC 2308, Section 3: SOA in Authority section for negative answers
	if negativeAnswer(&replyMsg, replyCode) && soa.authority() {
		replyMsg.Ns = append(replyMsg.Ns, soaAnswer(&q, soa))
	}
}

// replyType returns true if records with recordType should be included in the
// reply message for the given question.
func replyType(q *dns.Question, recordType uint16) bool {
	switch q.Qtype {
	case dns.TypeAXFR, dns.TypeANY, recordType:
		return true

	default:
		return false
	}
}

func negativeAnswer(replyMsg *dns.Msg, replyCode int) bool {
	return replyCode == dns.RcodeNameError || len(replyMsg.Answer) == 0
}

func soaAnswer(q *dns.Question, soa *SOA) *dns.SOA {
	return &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    soa.TTL,
		},
		Ns:      soa.NS,
		Mbox:    soa.Mbox,
		Serial:  soa.Serial,
		Refresh: soa.Refresh,
		Retry:   soa.Retry,
		Expire:  soa.Expire,
		Minttl:  soa.MinTTL,
	}
}
