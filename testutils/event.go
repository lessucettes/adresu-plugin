// testutils/event.go
package testutils

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

// PubKey constant for tests that don't need a specific author.
const TestPubKey = "d0debf246fb1265edf35a80e2be592025e8d812fc38e0e9cf5c63091a4639d85"

// MakeEvent is a shared helper to create a nostr.Event for tests.
// It uses a fixed seed for deterministic event IDs.
func MakeEvent(kind int, content, pubkey string, ts time.Time, tags ...nostr.Tag) *nostr.Event {
	// A fixed-seed random source ensures that generated IDs are the same across test runs,
	// making tests deterministic.
	localRand := rand.New(rand.NewSource(42))

	ev := &nostr.Event{
		Kind:      kind,
		Content:   content,
		PubKey:    pubkey,
		CreatedAt: nostr.Timestamp(ts.Unix()),
		Tags:      tags,
	}

	// Generate a simple, predictable ID for testing purposes.
	ev.ID = fmt.Sprintf("id-%d-%x", kind, localRand.Uint64())
	return ev
}

// MakeTextNote is a helper to create a Kind 1 text-note event for tests.
func MakeTextNote(pubkey, content string, ts time.Time) *nostr.Event {
	return MakeEvent(nostr.KindTextNote, content, pubkey, ts)
}
