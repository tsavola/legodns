// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package autocert is modeled after and built on
// https://golang.org/x/crypto/acme/autocert.
//
// See the top-level package for general documentation.
package autocert

import (
	"context"
	"crypto/tls"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/tsavola/acmedns"
	internal "github.com/tsavola/acmedns/internal/acme/autocert"
)

// DNS knows what hosts exist in which zones, and can create/update TXT records
// in those zones.  It doesn't have to be instantaneous.
type DNS interface {
	acmedns.DNS

	// ResolveZone checks the existence of a host.  If it is a known host in a
	// known zone, its domain name is returned.  In all other cases an error is
	// returned.
	//
	// Successful check of a nonexistent name should return an error with a
	// NotExist() method which returns true.
	ResolveZone(ctx context.Context, hostname string) (domain string, err error)
}

type Manager struct {
	Prompt      func(tosURL string) bool
	Cache       autocert.Cache
	DNS         DNS
	RenewBefore time.Duration
	Client      *acme.Client
	Email       string
	ForceRSA    bool

	DebugLog Logger // Defaults to nothingness

	initOnce sync.Once
	internal internal.Manager
}

func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.initOnce.Do(m.init)
	return m.internal.GetCertificate(hello)
}

func (m *Manager) init() {
	m.internal = internal.Manager{
		Prompt:      m.Prompt,
		Cache:       m.Cache,
		HostPolicy:  m.hostPolicy,
		RenewBefore: m.RenewBefore,
		Client:      m.Client,
		Email:       m.Email,
		ForceRSA:    m.ForceRSA,
		Verify:      m.verify,
	}
}

func (m *Manager) hostPolicy(ctx context.Context, host string) (err error) {
	if m.DebugLog != nil {
		m.DebugLog.Printf("autocert: %q", host)
	}

	_, err = m.DNS.ResolveZone(ctx, host+".")

	if m.DebugLog != nil && err != nil {
		m.DebugLog.Printf("autocert: %v", err)
	}

	return
}

func (m *Manager) verify(ctx context.Context, client *acme.Client, serverName string) (err error) {
	zone, err := m.DNS.ResolveZone(ctx, serverName+".")
	if err != nil {
	}

	err = acmedns.Verify(ctx, m.Client, m.DNS, serverName, zone)

	if err != nil && m.DebugLog != nil {
		m.DebugLog.Printf("autocert: %v", err)
	}

	return
}
