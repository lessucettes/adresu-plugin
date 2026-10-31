package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"fiatjaf.com/nostr"

	"github.com/lessucettes/adresu-plugin/pkg/adresu-kit/config"
)

// fixturePubKey returns a deterministic author identity for fixtures that only
// need a distinct author, not a usable point on the curve. Filters compare the
// decoded [32]byte identity; they never verify signatures.
func fixturePubKey(id byte) nostr.PubKey {
	var pk nostr.PubKey
	pk[0] = id
	return pk
}

func authoredEvent(pubkey nostr.PubKey, kind nostr.Kind) *nostr.Event {
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

// NIP-01 asks for lowercase hex, but relays decode public keys
// case-insensitively and hash the event exactly as received, so one keypair can
// arrive with any mix of hex casing. Per-author state keys on the decoded
// binary key, so every wire spelling must share one limiter. This is the only
// place casing exists; binary PubKey values have no case.
func TestWirePubkeyCasingDecodesToOneAuthor(t *testing.T) {
	canonical := fixturePubKey(0xab).Hex()
	upperCanonical := strings.ToUpper(canonical)
	if upperCanonical == canonical {
		t.Fatalf("fixture %q has no hex letters, so it cannot exercise casing", canonical)
	}

	parse := func(wirePubKey string) *nostr.Event {
		t.Helper()
		raw := fmt.Sprintf(
			`{"id":%q,"pubkey":%q,"created_at":1,"kind":1,"tags":[],"content":"content","sig":%q}`,
			strings.Repeat("0", 64), wirePubKey, strings.Repeat("0", 128),
		)
		var event nostr.Event
		if err := json.Unmarshal([]byte(raw), &event); err != nil {
			t.Fatalf("decode wire event with pubkey %q: %v", wirePubKey, err)
		}
		return &event
	}

	lower := parse(canonical)
	upper := parse(upperCanonical)
	if lower.PubKey != upper.PubKey {
		t.Fatalf("wire casing produced two identities: %s and %s", lower.PubKey.Hex(), upper.PubKey.Hex())
	}

	filter := newRateLimiterFilter(t, config.RateByPubKey)
	for i := 0; i < 2; i++ {
		if !rateLimitedEvent(t, filter, lower) {
			t.Fatalf("event %d was limited before the burst was exhausted", i+1)
		}
	}
	if rateLimitedEvent(t, filter, upper) {
		t.Fatal("an uppercase wire spelling of the same pubkey received a fresh burst")
	}
}
