package nip

import (
	"context"
	"math/bits"
	"strconv"
	"strings"
	"testing"

	"fiatjaf.com/nostr"
)

// difficultyOf is an independent leading-zero-bit oracle for the typed IDs.
func difficultyOf(id nostr.ID) int {
	count := 0
	for _, b := range id {
		if b == 0 {
			count += 8
			continue
		}
		count += bits.LeadingZeros8(b)
		break
	}
	return count
}

func TestIsPoWValidRejectsForgedEventID(t *testing.T) {
	// A nonce tag cannot prove work unless the ID is the hash of the event body.
	event := &nostr.Event{
		PubKey:    nostr.MustPubKeyFromHex("1111111111111111111111111111111111111111111111111111111111111111"),
		CreatedAt: nostr.Timestamp(1),
		Kind:      nostr.KindTextNote,
		Content:   "not actually mined",
		Tags:      nostr.Tags{{"nonce", "0", "16"}},
	}

	if IsPoWValid(context.Background(), event, 1) {
		t.Fatal("IsPoWValid accepted an event whose ID does not match its content")
	}
}

func TestIsPoWValidAcceptsMinedEvent(t *testing.T) {
	const difficulty = 8
	ctx := context.Background()

	// A control character in the content forces the canonical NIP-01 encoder:
	// mining and validation must agree on the same hash for such events.
	event := &nostr.Event{
		PubKey:    nostr.MustPubKeyFromHex("1111111111111111111111111111111111111111111111111111111111111111"),
		CreatedAt: nostr.Timestamp(1),
		Kind:      nostr.KindTextNote,
		Content:   "mined\x01",
	}
	var mined bool
	for nonce := 0; nonce < 1<<16; nonce++ {
		event.Tags = nostr.Tags{{"nonce", strconv.Itoa(nonce), strconv.Itoa(difficulty)}}
		event.ID = CanonicalEventID(ctx, event)
		if difficultyOf(event.ID) >= difficulty {
			mined = true
			break
		}
	}
	if !mined {
		t.Fatal("failed to mine a test event")
	}

	if !IsPoWValid(ctx, event, difficulty) {
		t.Fatal("IsPoWValid rejected a correctly mined event")
	}
	if IsPoWValid(ctx, event, difficulty+8) {
		t.Fatal("IsPoWValid accepted work below the required difficulty")
	}

	event.ID[31] ^= 0xff
	if IsPoWValid(ctx, event, difficulty) {
		t.Fatal("IsPoWValid accepted a mined ID that no longer matches the event body")
	}
}

func TestIsPoWValidRejectsClaimedDifficultyAboveActual(t *testing.T) {
	const (
		minimum = 8
		claimed = 12
	)
	ctx := context.Background()

	event := &nostr.Event{
		PubKey:    nostr.MustPubKeyFromHex("1111111111111111111111111111111111111111111111111111111111111111"),
		CreatedAt: nostr.Timestamp(1),
		Kind:      nostr.KindTextNote,
		Content:   "overclaimed",
	}
	var found bool
	for nonce := 0; nonce < 1<<16; nonce++ {
		event.Tags = nostr.Tags{{"nonce", strconv.Itoa(nonce), strconv.Itoa(claimed)}}
		event.ID = CanonicalEventID(ctx, event)
		if actual := difficultyOf(event.ID); actual >= minimum && actual < claimed {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("failed to find an event whose actual work is below its claimed difficulty")
	}

	if IsPoWValid(ctx, event, minimum) {
		t.Fatal("IsPoWValid accepted a nonce tag claiming more work than the ID demonstrates")
	}
}

func TestIsPoWValidHonorsWirePubKeyProvenance(t *testing.T) {
	const difficulty = 8
	pubKey := nostr.KeyOne.Public()
	event := &nostr.Event{
		PubKey:    pubKey,
		CreatedAt: nostr.Timestamp(1),
		Kind:      nostr.KindTextNote,
		Content:   "uppercase author",
	}
	ctx := WithWirePubKey(context.Background(), event, strings.ToUpper(pubKey.Hex()))

	var mined bool
	for nonce := 0; nonce < 1<<16; nonce++ {
		event.Tags = nostr.Tags{{"nonce", strconv.Itoa(nonce), strconv.Itoa(difficulty)}}
		event.ID = CanonicalEventID(ctx, event)
		if difficultyOf(event.ID) >= difficulty {
			mined = true
			break
		}
	}
	if !mined {
		t.Fatal("failed to mine an event for the uppercase wire pubkey")
	}

	if !IsPoWValid(ctx, event, difficulty) {
		t.Fatal("IsPoWValid rejected work mined over the uppercase wire pubkey")
	}
	if IsPoWValid(context.Background(), event, difficulty) {
		t.Fatal("IsPoWValid accepted the uppercase-authored ID without wire provenance")
	}
}

func TestIsPoWValidRequiresNonceTag(t *testing.T) {
	ctx := context.Background()
	event := &nostr.Event{
		PubKey:    nostr.MustPubKeyFromHex("1111111111111111111111111111111111111111111111111111111111111111"),
		CreatedAt: nostr.Timestamp(1),
		Kind:      nostr.KindTextNote,
		Content:   "mined",
	}
	event.ID = CanonicalEventID(ctx, event)

	if IsPoWValid(ctx, event, 1) {
		t.Fatal("IsPoWValid accepted an event without a nonce tag")
	}
	if !IsPoWValid(ctx, event, 0) {
		t.Fatal("IsPoWValid rejected an event when no difficulty is required")
	}
}
