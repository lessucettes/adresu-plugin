package reputation

import (
	"context"
	"testing"
	"time"

	"fiatjaf.com/nostr"
	"github.com/coder/websocket"
	kitrep "github.com/lessucettes/adresu-plugin/pkg/adresu-kit/reputation"
)

func TestCompletedMetadataMissKeepsLastVerifiedOutbox(t *testing.T) {
	key := nostr.Generate()
	pk := key.Public()
	event := signedList(t, key, "cached outbox")
	outbox := serveDiscoveryRelay(t, true, func(ctx context.Context, conn *websocket.Conn, sub string, _ nostr.Filter) {
		_ = sendDiscoveryEvent(t, ctx, conn, sub, event)
		_ = sendDiscoveryEOSE(t, ctx, conn, sub)
	})
	empty := serveDiscoveryRelay(t, false, func(ctx context.Context, conn *websocket.Conn, sub string, _ nostr.Filter) {
		_ = sendDiscoveryEOSE(t, ctx, conn, sub)
	})
	cfg := discoveryConfig(pk, wsTestURL(empty), wsTestURL(empty))
	source := newDiscoverySourceWithOptions(cfg, discoveryDialOptionsFor(outbox))
	source.cache.putMetadata(pk, kitrep.RelayList{Author: pk, CreatedAt: 1, EventID: nostr.ID{1}, WriteRelays: []string{secureTestURL(t, outbox, "relay.example.com")}}, time.Now().Add(-2*discoveryMetadataTTL))
	for i := 0; i < 2; i++ {
		got, err := source.Fetch(context.Background(), []nostr.PubKey{pk})
		if err != nil || got[pk].EventID != event.ID {
			t.Fatalf("completed miss erased verified metadata on attempt %d: %+v, %v", i, got, err)
		}
	}
}
