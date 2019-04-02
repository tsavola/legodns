package legodns

import (
	"context"

	"github.com/go-acme/lego/challenge/dns01"
)

const ttl = 1 // second

// DNS can create, update and remove TXT records.
type DNS interface {
	// ModifyTXTRecord creates, updates, or removes a TXT record.  It blocks
	// until the modification is complete or the context is done.
	ModifyTXTRecord(ctx context.Context, fqdn string, values []string, ttl int) error

	// ForgetTXTRecord removes a TXT record immediately or at some point in the
	// future.  It doesn't have to wait for the modification to be complete.
	// It's ok if the name doesn't exist.
	ForgetTXTRecord(fqdn string) error
}

// Provider can solve ACME dns-01 challenges.
type Provider struct {
	dns DNS
}

func NewProvider(dns DNS) *Provider {
	return &Provider{dns}
}

func (p *Provider) Present(domain, token, keyAuth string) error {
	fqdn, value := dns01.GetRecord(domain, keyAuth)
	return p.dns.ModifyTXTRecord(context.Background(), fqdn, []string{value}, ttl)
}

func (p *Provider) CleanUp(domain, token, keyAuth string) error {
	fqdn, _ := dns01.GetRecord(domain, keyAuth)
	return p.dns.ForgetTXTRecord(fqdn)
}
