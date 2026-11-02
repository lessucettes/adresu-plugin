package reputation

import (
	"context"
	"testing"

	"fiatjaf.com/nostr"
	"github.com/coder/websocket"
)

func TestRelayAuthReleasesOldSubscriptionSlot(t *testing.T) {
	seed := nostr.KeyOne.Public()
	relay := authRelayServer(t, func(ctx context.Context, conn *websocket.Conn, url string) {
		initial, ok := nextFrame(t, ctx, conn)
		if !ok {
			return
		}
		old := initial.stringAt(1)
		if !sendFrame(t, ctx, conn, []any{"AUTH", "one-subscription-slot"}) {
			return
		}
		event, ok := expectCollectorAuth(t, ctx, conn, url, "one-subscription-slot")
		if !ok {
			return
		}
		if !sendFrame(t, ctx, conn, []any{"OK", event.ID.Hex(), true, ""}) {
			return
		}
		frame, ok := nextFrame(t, ctx, conn)
		if !ok {
			return
		}
		if frame.command() != "CLOSE" || frame.stringAt(1) != old {
			_ = sendFrame(t, ctx, conn, []any{"CLOSED", frame.stringAt(1), "restricted: subscription limit"})
			return
		}
		frame, ok = nextFrame(t, ctx, conn)
		if !ok {
			return
		}
		if frame.command() != "REQ" || frame.stringAt(1) == old {
			t.Error("expected a fresh REQ after CLOSE")
			return
		}
		sub := frame.stringAt(1)
		_ = sendFrame(t, ctx, conn, []any{"EVENT", sub, signedList(t, nostr.KeyOne, "post-auth")})
		_ = sendFrame(t, ctx, conn, []any{"EOSE", sub})
	})
	cfg := testConfig(seed)
	cfg.Relays = []string{relay}
	got, err := (relaySource{cfg}).Fetch(context.Background(), []nostr.PubKey{seed})
	if err != nil || len(got) != 1 {
		t.Fatalf("AUTH exceeded a single subscription slot: %v, %v", got, err)
	}
}
