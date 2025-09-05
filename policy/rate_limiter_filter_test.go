// policy/rate_limiter_filter_test.go
package policy

import (
	"context"
	"testing"
	"time"

	"adresu-plugin/config"
	"adresu-plugin/testutils"

	"github.com/nbd-wtf/go-nostr"
	"github.com/stretchr/testify/require"
)

func TestRateLimiterFilter(t *testing.T) {
	ctx := context.Background()
	userA := "pubkey_A"
	userB := "pubkey_B"
	ip1 := "1.1.1.1"
	ip2 := "2.2.2.2"

	now := time.Now

	testCases := []struct {
		name            string
		cfg             *config.RateLimiterConfig
		sequence        []*nostr.Event
		ips             []string
		expectedActions []string
		sleepAfter      int // index at which we sleep before processing that event
	}{
		{
			name: "Filter disabled",
			cfg:  &config.RateLimiterConfig{Enabled: false},
			sequence: []*nostr.Event{
				testutils.MakeEvent(nostr.KindTextNote, "", userA, now()),
			},
			ips:             []string{ip1},
			expectedActions: []string{ActionAccept},
		},
		{
			name: "Default limit by IP",
			cfg: &config.RateLimiterConfig{
				Enabled:      true,
				By:           config.RateByIP,
				DefaultRate:  10,
				DefaultBurst: 1,
			},
			sequence: []*nostr.Event{
				testutils.MakeEvent(nostr.KindTextNote, "", userA, now()), // Accept (1/1 for ip1)
				testutils.MakeEvent(nostr.KindTextNote, "", userB, now()), // Reject (ip1 exhausted)
				testutils.MakeEvent(nostr.KindTextNote, "", userA, now()), // Accept (ip2 separate bucket)
			},
			ips:             []string{ip1, ip1, ip2},
			expectedActions: []string{ActionAccept, ActionReject, ActionAccept},
		},
		{
			name: "Default limit by PubKey",
			cfg: &config.RateLimiterConfig{
				Enabled:      true,
				By:           config.RateByPubKey,
				DefaultRate:  10,
				DefaultBurst: 1,
			},
			sequence: []*nostr.Event{
				testutils.MakeEvent(nostr.KindTextNote, "", userA, now()), // Accept (1/1 for userA)
				testutils.MakeEvent(nostr.KindTextNote, "", userA, now()), // Reject (userA exhausted)
				testutils.MakeEvent(nostr.KindTextNote, "", userB, now()), // Accept (userB separate bucket)
			},
			ips:             []string{ip1, ip2, ip1},
			expectedActions: []string{ActionAccept, ActionReject, ActionAccept},
		},
		{
			name: "Limit by both IP and PubKey",
			cfg: &config.RateLimiterConfig{
				Enabled:      true,
				By:           config.RateByBoth,
				DefaultRate:  10,
				DefaultBurst: 1,
			},
			sequence: []*nostr.Event{
				testutils.MakeEvent(nostr.KindTextNote, "", userA, now()), // ip1+userA: Accept
				testutils.MakeEvent(nostr.KindTextNote, "", userB, now()), // ip1 exhausted: Reject
				testutils.MakeEvent(nostr.KindTextNote, "", userA, now()), // userA exhausted (even on ip2): Reject
			},
			ips:             []string{ip1, ip1, ip2},
			expectedActions: []string{ActionAccept, ActionReject, ActionReject},
		},
		{
			name: "Specific rule is applied over default",
			cfg: &config.RateLimiterConfig{
				Enabled:      true,
				By:           config.RateByPubKey,
				DefaultRate:  10,
				DefaultBurst: 5, // default is permissive
				Rules: []config.RateLimitRule{
					{
						Description: "Strict for Kind 7",
						Kinds:       []int{7},
						Rate:        10,
						Burst:       1, // strict rule overrides default
					},
				},
			},
			sequence: []*nostr.Event{
				testutils.MakeEvent(7, "", userA, now()),                  // Accept (1/1 for strict rule)
				testutils.MakeEvent(7, "", userA, now()),                  // Reject (strict rule exhausted)
				testutils.MakeEvent(nostr.KindTextNote, "", userA, now()), // Accept (default bucket 1/5)
			},
			ips:             []string{ip1, ip1, ip1},
			expectedActions: []string{ActionAccept, ActionReject, ActionAccept},
		},
		{
			name: "Limiter refills tokens over time",
			cfg: &config.RateLimiterConfig{
				Enabled:      true,
				By:           config.RateByPubKey,
				DefaultRate:  1, // 1 token per second
				DefaultBurst: 1,
			},
			sequence: []*nostr.Event{
				testutils.MakeEvent(nostr.KindTextNote, "", userA, now()), // Accept
				testutils.MakeEvent(nostr.KindTextNote, "", userA, now()), // Reject
				testutils.MakeEvent(nostr.KindTextNote, "", userA, now()), // Accept (after sleep)
			},
			ips:             []string{ip1, ip1, ip1},
			expectedActions: []string{ActionAccept, ActionReject, ActionAccept},
			// Sleep before processing event at index 2 (the 3rd event).
			sleepAfter: 2,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			filter := NewRateLimiterFilter(tc.cfg)

			for i, ev := range tc.sequence {
				if tc.sleepAfter > 0 && i == tc.sleepAfter {
					// Wait long enough for at least one token to refill.
					rate := tc.cfg.DefaultRate
					if r, ok := filter.kindToRule[ev.Kind]; ok {
						rate = r.Rate
					}
					if rate > 0 {
						sleep := time.Duration(1/rate*float64(time.Second)) + 10*time.Millisecond
						time.Sleep(sleep)
					}
				}

				res := filter.Check(ctx, ev, tc.ips[i])
				require.Equal(t, tc.expectedActions[i], res.Action, "mismatch at event index %d", i)
			}
		})
	}
}
