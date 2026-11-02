package reputation

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"fiatjaf.com/nostr"
)

func signedRelayListEvent(t *testing.T, tags nostr.Tags) nostr.Event {
	t.Helper()
	event := nostr.Event{Kind: nostr.KindRelayListMetadata, CreatedAt: nostr.Timestamp(time.Now().Unix()), Tags: tags}
	if err := event.Sign(nostr.KeyOne); err != nil {
		t.Fatal(err)
	}
	return event
}

func TestParseRelayListExtractsOnlyVerifiedWriteRelays(t *testing.T) {
	event := signedRelayListEvent(t, nostr.Tags{
		{"r", "wss://one.example"},
		{"r", "wss://two.example", "write"},
		{"r", "wss://read.example", "read"},
		{"r", "wss://both.example", ""},
		{"r", "ws://insecure.example"},
		{"r", "wss://user:pass@secret.example"},
		{"r", "wss://fragment.example/#part"},
		{"r", "wss://one.example"},
		{"r", "wss://three.example", "unknown"},
		{"r", "wss://four.example"},
		{"r", "wss://five.example"},
	})
	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	list, err := ParseRelayList(context.Background(), raw, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"wss://one.example", "wss://two.example", "wss://both.example", "wss://four.example",
	}
	if len(list.WriteRelays) != len(want) {
		t.Fatalf("write relays = %v, want %v", list.WriteRelays, want)
	}
	for i := range want {
		if list.WriteRelays[i] != want[i] {
			t.Fatalf("write relays = %v, want %v", list.WriteRelays, want)
		}
	}
	if list.Author != event.PubKey || list.EventID != event.ID || list.CreatedAt != event.CreatedAt {
		t.Fatalf("metadata identity = %+v", list)
	}
}

func TestParseRelayListSignedEmptyMetadata(t *testing.T) {
	event := signedRelayListEvent(t, nostr.Tags{
		{"r", "wss://readonly.example", "read"},
		{"client", "test"},
	})
	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	list, err := ParseRelayList(context.Background(), raw, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(list.WriteRelays) != 0 {
		t.Fatalf("read-only metadata produced write relays: %v", list.WriteRelays)
	}
}

func TestParseRelayListRejectsInvalidMetadata(t *testing.T) {
	for _, name := range []string{"kind", "future", "id", "signature", "tags", "relay_tags", "json", "cancelled"} {
		t.Run(name, func(t *testing.T) {
			tags := nostr.Tags{{"r", "wss://one.example"}}
			event := signedRelayListEvent(t, tags)
			ctx := context.Background()
			switch name {
			case "kind":
				event.Kind = 3
			case "future":
				event.CreatedAt = nostr.Timestamp(time.Now().Add(time.Hour).Unix())
				if err := event.Sign(nostr.KeyOne); err != nil {
					t.Fatal(err)
				}
			case "id":
				event.ID[0] ^= 1
			case "signature":
				event.Sig[0] ^= 1
			case "tags":
				event.Tags = make(nostr.Tags, maxRelayListTotalTags+1)
				if err := event.Sign(nostr.KeyOne); err != nil {
					t.Fatal(err)
				}
			case "relay_tags":
				event.Tags = make(nostr.Tags, maxRelayListTags+1)
				for i := range event.Tags {
					event.Tags[i] = nostr.Tag{"r", "wss://relay.example"}
				}
				if err := event.Sign(nostr.KeyOne); err != nil {
					t.Fatal(err)
				}
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			raw, err := json.Marshal(event)
			if err != nil {
				t.Fatal(err)
			}
			if name == "json" {
				raw = []byte(`{"kind":10002`)
			}
			if _, err := ParseRelayList(ctx, raw, time.Now()); err == nil {
				t.Fatal("invalid metadata accepted")
			}
		})
	}
}

func TestParseRelayListRejectsOversizedRaw(t *testing.T) {
	raw := []byte(`{"kind":10002,"tags":[],"content":"` + strings.Repeat("x", maxRelayListBytes) + `"}`)
	if _, err := ParseRelayList(context.Background(), raw, time.Now()); err == nil {
		t.Fatal("oversized metadata accepted")
	}
}

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
