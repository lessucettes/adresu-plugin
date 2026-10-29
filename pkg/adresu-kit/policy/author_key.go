package policy

import (
	"strings"

	"github.com/nbd-wtf/go-nostr"
)

// authorKey returns the canonical key for an event author's per-author state.
//
// NIP-01 spells public keys as lowercase hex, but relays such as strfry hash the
// event exactly as received and decode hex case-insensitively, so a client can
// present the same keypair with any mix of uppercase and lowercase digits. Keys
// for rate limiters, activity counters and approval caches therefore have to be
// canonicalized, or one author could reset its state by changing the casing of
// its pubkey.
func authorKey(event *nostr.Event) string {
	return strings.ToLower(event.PubKey)
}
