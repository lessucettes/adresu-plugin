// nip/13_pow.go
package nip

import (
	"context"
	"strconv"
	"strings"

	"fiatjaf.com/nostr"
	"fiatjaf.com/nostr/nip13"
)

// IsPoWValid checks if an event has a valid Proof of Work of at least minDifficulty.
func IsPoWValid(ctx context.Context, event *nostr.Event, minDifficulty int) bool {
	if minDifficulty <= 0 {
		return true
	}
	if event == nil || CanonicalEventID(ctx, event) != event.ID {
		// Without matching the ID to the event body the nonce tag and the
		// leading zero bits prove nothing about this event.
		return false
	}
	nonceTag := event.Tags.FindLast("nonce")
	if len(nonceTag) < 3 {
		return false
	}
	claimedDifficulty, err := strconv.Atoi(strings.TrimSpace(nonceTag[2]))
	if err != nil {
		return false
	}
	if claimedDifficulty < minDifficulty {
		return false
	}
	return nip13.Difficulty(event.ID) >= claimedDifficulty
}
