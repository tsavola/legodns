// Copyright (c) 2018 Timo Savola. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package acmedns

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/crypto/acme"
)

const (
	challengeType = "dns-01"
)

const (
	challengeNode = "_acme-challenge"
	challengeTTL  = 1 // second
)

// DNS can create, update, and remove TXT records on name servers.  It doesn't
// have to be instantaneous.
type DNS interface {
	// ModifyTXTRecord creates, updates, or removes a TXT record.  It blocks
	// until the modification is complete or the context is done.
	ModifyTXTRecord(ctx context.Context, zone, node string, values []string, ttl uint32) error

	// ForgetTXTRecord removes a TXT record at some point in the future.  It
	// doesn't wait for the modification to be complete.
	ForgetTXTRecord(zone, node string) error
}

func Verify(ctx context.Context, client *acme.Client, dns DNS, serverName, zone string) (err error) {
	authz, err := client.Authorize(ctx, serverName)
	if err != nil {
		return
	}

	switch authz.Status {
	case acme.StatusValid:
		// ok

	case acme.StatusInvalid:
		err = fmt.Errorf("acmedns: invalid authorization %q", authz.URI)

	default:
		_, err = acquireAuthorization(ctx, client, authz, dns, zone)
	}
	return
}

func acquireAuthorization(ctx context.Context, client *acme.Client, authz *acme.Authorization, dns DNS, zone string) (*acme.Authorization, error) {
	combos := authz.Combinations
	if len(combos) == 0 {
		combo := make([]int, len(authz.Challenges))
		for i := range authz.Challenges {
			combo[i] = i
		}
		combos = [][]int{combo}
	}

	var (
		accepted *acme.Challenge
		err      error
	)

	for _, combo := range combos {
		if len(combo) == 1 {
			if i := combo[0]; i < len(authz.Challenges) {
				chal := authz.Challenges[i]
				err = fulfillChallenge(ctx, client, chal, dns, zone)
				if err == nil {
					defer dns.ForgetTXTRecord(zone, challengeNode) // After WaitAuthorization
					accepted, err = client.Accept(ctx, chal)
					if err == nil {
						break
					}
				}
			}
		}
	}

	if accepted == nil {
		if err == nil {
			err = errors.New("acmedns: no supported challenge combinations")
		}
		return nil, err
	}

	return client.WaitAuthorization(ctx, authz.URI)
}

func fulfillChallenge(ctx context.Context, client *acme.Client, chal *acme.Challenge, dns DNS, zone string) error {
	if chal.Type != challengeType {
		return errors.New("acmedns: unsupported challenge types")
	}

	value, err := client.DNS01ChallengeRecord(chal.Token)
	if err != nil {
		return err
	}

	return dns.ModifyTXTRecord(ctx, zone, challengeNode, []string{value}, challengeTTL)
}
