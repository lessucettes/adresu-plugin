package reputation

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"fiatjaf.com/nostr"
	"github.com/coder/websocket"
)

func TestQueryRelayNIP42CompletesGenericTransport(t *testing.T) {
	seed := nostr.KeyOne.Public()
	pre := signedList(t, nostr.KeyOne, "pre-auth", nostr.Generate().Public())
	post := signedList(t, nostr.KeyOne, "post-auth", nostr.Generate().Public())
	relay := authRelayServer(t, func(ctx context.Context, conn *websocket.Conn, relayURL string) {
		frame, ok := nextFrame(t, ctx, conn)
		if !ok || frame.command() != "REQ" {
			t.Errorf("initial frame was not REQ")
			return
		}
		oldSubscription := frame.stringAt(1)
		if !sendFrame(t, ctx, conn, []any{"AUTH", "generic-challenge"}) ||
			!sendFrame(t, ctx, conn, []any{"EVENT", oldSubscription, pre}) ||
			!sendFrame(t, ctx, conn, []any{"EOSE", oldSubscription}) {
			return
		}
		event, ok := expectCollectorAuth(t, ctx, conn, relayURL, "generic-challenge")
		if !ok {
			return
		}
		if !sendFrame(t, ctx, conn, []any{"OK", event.ID.Hex(), true, ""}) {
			return
		}
		subscription, ok := expectQuery(t, ctx, conn, oldSubscription)
		if !ok {
			return
		}
		_ = sendFrame(t, ctx, conn, []any{"EVENT", subscription, post})
		_ = sendFrame(t, ctx, conn, []any{"EOSE", subscription})
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	events, err := queryRelay(ctx, relay, []nostr.PubKey{seed}, nostr.KindFollowList, newOperatorClient(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("pre-auth data leaked through generic transport: %d events", len(events))
	}
	var event nostr.Event
	if err := json.Unmarshal(events[0], &event); err != nil || event.ID != post.ID {
		t.Fatalf("completed event = %+v, %v", event, err)
	}
}

func TestQueryRelayPrefiltersRequestedKindAndAuthor(t *testing.T) {
	seed := nostr.KeyOne.Public()
	other := nostr.Generate()
	follow := signedList(t, nostr.KeyOne, "follow")
	metadata := signedMetadata(t, nostr.KeyOne, time.Now().Unix(), nostr.Tags{{"r", "wss://relay.example"}})
	unrelated := signedList(t, other, "unrelated")
	relay := serveDiscoveryRelay(t, false, func(ctx context.Context, conn *websocket.Conn, sub string, filter nostr.Filter) {
		for _, event := range []nostr.Event{follow, metadata, unrelated} {
			_ = sendDiscoveryEvent(t, ctx, conn, sub, event)
		}
		_ = sendDiscoveryEOSE(t, ctx, conn, sub)
	})
	events, err := queryRelay(context.Background(), wsTestURL(relay), []nostr.PubKey{seed}, nostr.KindRelayListMetadata, newOperatorClient(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("generic query returned %d events, want one metadata event", len(events))
	}
	var event nostr.Event
	if err := json.Unmarshal(events[0], &event); err != nil || event.ID != metadata.ID || event.Kind != nostr.KindRelayListMetadata {
		t.Fatalf("generic query returned %+v, %v", event, err)
	}
}

func TestManagerSelectsDiscoverySource(t *testing.T) {
	cfg := testConfig(nostr.KeyOne.Public())
	manager := NewManager(context.Background(), nil)
	cfg.DiscoverRelays = true
	cfg.DiscoveryRelays = []string{"wss://indexer.example"}
	if _, ok := manager.newSource(cfg).(*discoverySource); !ok {
		t.Fatal("discover_relays did not select the discovery wrapper")
	}
	cfg.DiscoverRelays = false
	if _, ok := manager.newSource(cfg).(relaySource); !ok {
		t.Fatal("disabled discovery did not keep the fixed relay source")
	}
}
