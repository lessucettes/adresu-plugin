package nip

import (
	"strconv"
	"strings"
	"testing"

	"github.com/nbd-wtf/go-nostr"
)

func TestCountLeadingZeroBits(t *testing.T) {
	tests := []struct {
		name string
		id   string
		want int
	}{
		{"all zero", strings.Repeat("0", 64), 256},
		{"one", "1" + strings.Repeat("0", 63), 3},
		{"eight", "00ff" + strings.Repeat("0", 60), 8},
		{"twelve", "000f" + strings.Repeat("0", 60), 12},
		{"non hex stops counting", "000z", 12},
		{"short string", "00", 8},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CountLeadingZeroBits(tt.id); got != tt.want {
				t.Fatalf("CountLeadingZeroBits(%q) = %d, want %d", tt.id, got, tt.want)
			}
		})
	}
}

func TestIsPoWValidRejectsForgedEventID(t *testing.T) {
	// A nonce tag cannot prove work unless the ID is the hash of the event body.
	event := &nostr.Event{
		ID:        strings.Repeat("0", 64),
		PubKey:    strings.Repeat("1", 64),
		CreatedAt: nostr.Timestamp(1),
		Kind:      nostr.KindTextNote,
		Content:   "not actually mined",
		Tags:      nostr.Tags{{"nonce", "0", "16"}},
	}

	if IsPoWValid(event, 1) {
		t.Fatal("IsPoWValid accepted an event whose ID does not match its content")
	}
}

func TestIsPoWValidAcceptsMinedEvent(t *testing.T) {
	const difficulty = 8

	event := &nostr.Event{
		PubKey:    strings.Repeat("1", 64),
		CreatedAt: nostr.Timestamp(1),
		Kind:      nostr.KindTextNote,
		Content:   "mined",
	}
	var mined bool
	for nonce := 0; nonce < 1<<16; nonce++ {
		event.Tags = nostr.Tags{{"nonce", strconv.Itoa(nonce), strconv.Itoa(difficulty)}}
		event.ID = event.GetID()
		if CountLeadingZeroBits(event.ID) >= difficulty {
			mined = true
			break
		}
	}
	if !mined {
		t.Fatal("failed to mine a test event")
	}

	if !IsPoWValid(event, difficulty) {
		t.Fatal("IsPoWValid rejected a correctly mined event")
	}
	event.ID = strings.ToUpper(event.ID)
	if !IsPoWValid(event, difficulty) {
		t.Fatal("IsPoWValid rejected the same hash in uppercase hex")
	}
	if IsPoWValid(event, difficulty+8) {
		t.Fatal("IsPoWValid accepted work below the required difficulty")
	}
}

func TestIsPoWValidRequiresNonceTag(t *testing.T) {
	event := &nostr.Event{
		PubKey:    strings.Repeat("1", 64),
		CreatedAt: nostr.Timestamp(1),
		Kind:      nostr.KindTextNote,
		Content:   "mined",
	}
	event.ID = event.GetID()

	if IsPoWValid(event, 1) {
		t.Fatal("IsPoWValid accepted an event without a nonce tag")
	}
	if !IsPoWValid(event, 0) {
		t.Fatal("IsPoWValid rejected an event when no difficulty is required")
	}
}
