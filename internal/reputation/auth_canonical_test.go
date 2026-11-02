package reputation

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"fiatjaf.com/nostr"
	"github.com/coder/websocket"
	"github.com/lessucettes/adresu-plugin/pkg/adresu-kit/nip"
)

func TestRelayAuthAcceptsNewChallengeAfterSuccess(t *testing.T) {
	auth := newRelayAuth()
	auth.authenticated = true
	auth.challenge = "old"
	auth.attempts = 1
	frame := []json.RawMessage{json.RawMessage(`"AUTH"`), json.RawMessage(`"new"`)}
	send, err := auth.acceptChallenge(frame)
	if err != nil || !send || auth.authenticated {
		t.Fatalf("new connection challenge was ignored: send=%v, err=%v", send, err)
	}
}

func TestRelayAuthSignsCanonicalControlCharacters(t *testing.T) {
	seed := nostr.KeyOne.Public()
	relay := authRelayServer(t, func(ctx context.Context, conn *websocket.Conn, url string) {
		initial, ok := nextFrame(t, ctx, conn)
		if !ok {
			return
		}
		if !sendFrame(t, ctx, conn, []any{"AUTH", "challenge\x00\b\f"}) {
			return
		}
		frame, ok := nextFrame(t, ctx, conn)
		if !ok {
			return
		}
		if frame.command() != "AUTH" {
			t.Error("expected AUTH")
			return
		}
		var event nostr.Event
		if err := json.Unmarshal(frame[1], &event); err != nil {
			t.Error(err)
			return
		}
		valid, err := nip.CheckEventSignature(ctx, &event)
		if event.ID != nip.CanonicalEventID(ctx, &event) || err != nil || !valid {
			t.Error("AUTH did not sign canonical NIP-01 bytes")
			return
		}
		if !sendFrame(t, ctx, conn, []any{"OK", event.ID.Hex(), true, ""}) {
			return
		}
		subscription, ok := expectQuery(t, ctx, conn, initial.stringAt(1))
		if !ok {
			return
		}
		_ = sendFrame(t, ctx, conn, []any{"EOSE", subscription})
	})
	cfg := testConfig(seed)
	cfg.Relays = []string{relay}
	cfg.FetchTimeout = time.Second
	if _, err := (relaySource{cfg}).Fetch(context.Background(), []nostr.PubKey{seed}); err != nil {
		t.Fatal(err)
	}
}
