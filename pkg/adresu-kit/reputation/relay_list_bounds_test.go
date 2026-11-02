package reputation

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"fiatjaf.com/nostr"
)

func TestRelayMetadataBoundsCachedURLLength(t *testing.T) {
	event := signedRelayListEvent(t, nostr.Tags{
		{"r", "wss://relay.example/" + strings.Repeat("x", 2048)},
		{"r", "wss://relay.example/" + strings.Repeat("é", 512)},
		{"r", "wss://usable.example"},
	})
	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	list, err := ParseRelayList(context.Background(), raw, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(list.WriteRelays) != 1 || list.WriteRelays[0] != "wss://usable.example" {
		t.Fatalf("oversized URL retained: count=%d", len(list.WriteRelays))
	}
}
