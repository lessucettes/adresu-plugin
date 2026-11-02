package reputation

import (
	"context"
	"testing"
	"time"

	"fiatjaf.com/nostr"
	"github.com/coder/websocket"
)

func TestDiscoveryAuthenticatesMetadataAndReauthenticatesOutbox(t *testing.T) {
	seed := nostr.KeyOne.Public()
	wanted := signedList(t, nostr.KeyOne, "final authenticated list", nostr.Generate().Public())
	stale := signedList(t, nostr.KeyOne, "discarded generation", nostr.Generate().Public())
	authenticate := func(ctx context.Context, conn *websocket.Conn, url, sub, challenge string) (string, nostr.Event, bool) {
		if !sendFrame(t, ctx, conn, []any{"AUTH", challenge}) {
			return "", nostr.Event{}, false
		}
		event, ok := expectCollectorAuth(t, ctx, conn, url, challenge)
		if !ok || !sendFrame(t, ctx, conn, []any{"OK", event.ID.Hex(), true, ""}) {
			return "", nostr.Event{}, false
		}
		next, ok := expectQuery(t, ctx, conn, sub)
		return next, event, ok
	}
	var outboxURL string
	outbox := serveDiscoveryRelay(t, true, func(ctx context.Context, conn *websocket.Conn, sub string, _ nostr.Filter) {
		first, firstAuth, ok := authenticate(ctx, conn, outboxURL, sub, "outbox-first")
		if !ok {
			return
		}
		if !sendFrame(t, ctx, conn, []any{"EVENT", first, stale}) || !sendFrame(t, ctx, conn, []any{"AUTH", "outbox-second"}) {
			return
		}
		secondAuth, ok := expectCollectorAuth(t, ctx, conn, outboxURL, "outbox-second")
		if !ok {
			return
		}
		// An old ACK and frames from the retired subscription cannot complete
		// the newly authenticated generation.
		if !sendFrame(t, ctx, conn, []any{"OK", firstAuth.ID.Hex(), true, ""}) || !sendFrame(t, ctx, conn, []any{"OK", secondAuth.ID.Hex(), true, ""}) {
			return
		}
		second, ok := expectQuery(t, ctx, conn, first)
		if !ok {
			return
		}
		_ = sendFrame(t, ctx, conn, []any{"EVENT", first, stale})
		_ = sendFrame(t, ctx, conn, []any{"EOSE", first})
		_ = sendFrame(t, ctx, conn, []any{"EVENT", second, wanted})
		_ = sendFrame(t, ctx, conn, []any{"EOSE", second})
	})
	outboxURL = secureTestURL(t, outbox, "relay.example.com")
	var bootstrapURL string
	bootstrap := serveDiscoveryRelay(t, false, func(ctx context.Context, conn *websocket.Conn, sub string, filter nostr.Filter) {
		if len(filter.Kinds) != 1 || filter.Kinds[0] != nostr.KindRelayListMetadata {
			t.Errorf("unexpected metadata filter: %+v", filter)
			return
		}
		current, _, ok := authenticate(ctx, conn, bootstrapURL, sub, "metadata")
		if !ok {
			return
		}
		_ = sendFrame(t, ctx, conn, []any{"EVENT", current, signedMetadata(t, nostr.KeyOne, time.Now().Unix(), nostr.Tags{{"r", outboxURL, "write"}})})
		_ = sendFrame(t, ctx, conn, []any{"EOSE", current})
	})
	bootstrapURL = wsTestURL(bootstrap)
	fixed := serveDiscoveryRelay(t, false, func(ctx context.Context, conn *websocket.Conn, sub string, _ nostr.Filter) {
		_ = sendDiscoveryEOSE(t, ctx, conn, sub)
	})
	source := newDiscoverySourceWithOptions(discoveryConfig(seed, wsTestURL(fixed), bootstrapURL), discoveryDialOptionsFor(outbox))
	got, err := source.Fetch(context.Background(), []nostr.PubKey{seed})
	if err != nil || got[seed].EventID != wanted.ID {
		t.Fatalf("authenticated discovery returned wrong generation: %+v, %v", got, err)
	}
}
