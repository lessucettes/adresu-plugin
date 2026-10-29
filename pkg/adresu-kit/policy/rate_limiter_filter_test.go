package policy

import (
	"context"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"

	"github.com/lessucettes/adresu-plugin/pkg/adresu-kit/config"
)

func newRateLimiterFilter(t *testing.T, by config.RateLimiterBy) *RateLimiterFilter {
	t.Helper()
	filter, err := NewRateLimiterFilter(&config.RateLimiterConfig{
		Enabled:      true,
		By:           by,
		CacheSize:    100,
		TTL:          time.Minute,
		DefaultRate:  1000,
		DefaultBurst: 1000,
		Rules: []config.RateLimitRule{{
			Description: "notes",
			Kinds:       []int{nostr.KindTextNote},
			Rate:        0.000001,
			Burst:       2,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return filter
}

func rateLimitedMatch(t *testing.T, filter *RateLimiterFilter, pubkey, remoteIP string) bool {
	t.Helper()
	res, err := filter.Match(context.Background(), &nostr.Event{Kind: nostr.KindTextNote, PubKey: pubkey}, map[string]any{"remote_ip": remoteIP})
	if err != nil {
		t.Fatal(err)
	}
	return res.Allowed
}

func TestRateLimiterEnforcesBurstPerPubKey(t *testing.T) {
	filter := newRateLimiterFilter(t, config.RateByPubKey)

	for i := 0; i < 2; i++ {
		if !rateLimitedMatch(t, filter, "pk-1", "") {
			t.Fatalf("event %d was limited before the burst was exhausted", i+1)
		}
	}
	if rateLimitedMatch(t, filter, "pk-1", "") {
		t.Fatal("event above the burst was allowed")
	}
	if !rateLimitedMatch(t, filter, "pk-2", "") {
		t.Fatal("a different pubkey shares the same limiter")
	}
}

func TestRateLimiterWithOmittedByStillLimits(t *testing.T) {
	// An empty "by" is a legal TOML value; an enabled filter must not become a no-op.
	filter := newRateLimiterFilter(t, "")

	for i := 0; i < 2; i++ {
		if !rateLimitedMatch(t, filter, "pk-1", "203.0.113.1") {
			t.Fatalf("event %d was limited before the burst was exhausted", i+1)
		}
	}
	if rateLimitedMatch(t, filter, "pk-1", "203.0.113.1") {
		t.Fatal("enabled rate limiter with an empty by setting did not limit anything")
	}
}

func TestRateLimiterZeroRateIsUnlimited(t *testing.T) {
	filter, err := NewRateLimiterFilter(&config.RateLimiterConfig{
		Enabled:      true,
		By:           config.RateByPubKey,
		DefaultRate:  0,
		DefaultBurst: 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 10; i++ {
		if !rateLimitedMatch(t, filter, "pk-1", "") {
			t.Fatal("zero rate must mean unlimited")
		}
	}
}
