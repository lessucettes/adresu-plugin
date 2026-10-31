package policy

import "fiatjaf.com/nostr"

// authorKey returns the canonical key for an event author's per-author state.
//
// The decoded event already carries the author identity as a binary public key,
// so relay-side hex casing cannot produce two spellings of the same author:
// every filter keys rate limiters, activity counters and approval caches on the
// same [32]byte value for one keypair.
func authorKey(event *nostr.Event) nostr.PubKey {
	return event.PubKey
}
