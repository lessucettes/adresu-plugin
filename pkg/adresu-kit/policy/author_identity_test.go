package policy

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"

	"github.com/lessucettes/adresu-plugin/pkg/adresu-kit/config"
)

// authorPubkeys returns one author's public key in canonical lowercase hex and
// in an uppercase variant. NIP-01 asks for lowercase hex, but strfry decodes
// public keys case-insensitively and hashes the event exactly as received, so
// both spellings are admitted events signed by the same keypair.
func authorPubkeys(t *testing.T) (lower, upper string) {
	t.Helper()
	pk, err := nostr.GetPublicKey(nostr.GeneratePrivateKey())
	if err != nil {
		t.Fatal(err)
	}
	return pk, strings.ToUpper(pk)
}

func authoredEvent(pubkey string, kind int) *nostr.Event {
	return &nostr.Event{Kind: kind, PubKey: pubkey, Content: "content"}
}

func rateLimitedEvent(t *testing.T, filter *RateLimiterFilter, event *nostr.Event) bool {
	t.Helper()
	res, err := filter.Match(context.Background(), event, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	return res.Allowed
}

func repostEventAllowed(t *testing.T, filter *RepostAbuseFilter, event *nostr.Event) bool {
	t.Helper()
	res, err := filter.Match(context.Background(), event, nil)
	if err != nil {
		t.Fatal(err)
	}
	return res.Allowed
}

// Every per-author state store must key on the canonical lowercase public key;
// otherwise one keypair can reset its limits and counters by changing the case
// of its pubkey.
func TestRateLimiterTreatsPubkeyCaseVariantsAsOneAuthor(t *testing.T) {
	lower, upper := authorPubkeys(t)
	filter := newRateLimiterFilter(t, config.RateByPubKey)

	for i := 0; i < 2; i++ {
		if !rateLimitedEvent(t, filter, authoredEvent(lower, nostr.KindTextNote)) {
			t.Fatalf("event %d was limited before the burst was exhausted", i+1)
		}
	}
	if rateLimitedEvent(t, filter, authoredEvent(upper, nostr.KindTextNote)) {
		t.Fatal("an uppercase spelling of the same pubkey received a fresh burst")
	}
}

func TestEphemeralChatTreatsPubkeyCaseVariantsAsOneAuthor(t *testing.T) {
	lower, upper := authorPubkeys(t)
	filter := newEphemeralChatFilter(t, ephemeralChatConfig())

	event := authoredEvent(lower, ephemeralChatKind)
	if res, err := filter.Match(context.Background(), event, nil); err != nil || !res.Allowed {
		t.Fatalf("first message = (%v, %v), want allowed", res, err)
	}
	event.PubKey = upper
	if res, err := filter.Match(context.Background(), event, nil); err != nil || res.Allowed {
		t.Fatalf("casing variant = (%v, %v), want rate-limited as the same author", res, err)
	}
}

func TestRepostAbuseTreatsPubkeyCaseVariantsAsOneAuthor(t *testing.T) {
	lower, upper := authorPubkeys(t)
	filter, err := NewRepostAbuseFilter(&config.RepostAbuseFilterConfig{
		Enabled:   true,
		MaxRatio:  0.2,
		MinEvents: 5,
		CacheSize: 100,
		CacheTTL:  time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 5; i++ {
		if !repostEventAllowed(t, filter, authoredEvent(lower, nostr.KindTextNote)) {
			t.Fatalf("original post %d was rejected", i+1)
		}
	}
	// 1/6 = 16.7% stays below the 20% limit, 2/7 = 28.6% crosses it.
	if !repostEventAllowed(t, filter, authoredEvent(lower, nostr.KindRepost)) {
		t.Fatal("first repost was rejected")
	}
	if repostEventAllowed(t, filter, authoredEvent(upper, nostr.KindRepost)) {
		t.Fatal("a casing variant bypassed the repost ratio of the same author")
	}
}

func TestEmergencyFilterTreatsPubkeyCaseVariantsAsOneAuthor(t *testing.T) {
	lower, upper := authorPubkeys(t)
	other, _ := authorPubkeys(t)

	filter, err := NewEmergencyFilter(&config.EmergencyFilterConfig{
		Enabled:      true,
		NewKeysRate:  0.000001,
		NewKeysBurst: 2,
		CacheSize:    100,
		TTL:          time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}

	// The second spelling is the same author, so it must not spend the second
	// new-key allowance: another genuinely new pubkey still fits in the burst.
	if !emergencyMatch(t, filter, lower, "") {
		t.Fatal("first new pubkey was rejected")
	}
	if !emergencyMatch(t, filter, upper, "") {
		t.Fatal("casing variant was rejected as a new pubkey")
	}
	if !emergencyMatch(t, filter, other, "") {
		t.Fatal("casing variant spent a new-key token that belongs to the same author")
	}
}
