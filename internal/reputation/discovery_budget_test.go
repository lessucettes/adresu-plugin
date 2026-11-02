package reputation

import (
	"context"
	"strings"
	"testing"
	"time"

	"fiatjaf.com/nostr"
	"github.com/coder/websocket"
)

func TestDiscoveryGroupAggregateByteBudget(t *testing.T) {
	seed := nostr.KeyOne.Public()
	// Deliberately unsigned: the budget must apply before signature parsing.
	event := map[string]any{"pubkey": seed.Hex(), "kind": 3, "content": strings.Repeat("x", (1<<20)-512)}
	relay := serveDiscoveryRelay(t, false, func(ctx context.Context, conn *websocket.Conn, sub string, _ nostr.Filter) {
		for i := 0; i < 6; i++ {
			if !sendDiscoveryEvent(t, ctx, conn, sub, event) {
				return
			}
		}
		_ = sendDiscoveryEOSE(t, ctx, conn, sub)
	})
	cfg := discoveryConfig(seed, wsTestURL(relay), wsTestURL(relay))
	cfg.FetchTimeout = 10 * time.Second
	source := newDiscoverySourceWithOptions(cfg, discoveryDialOptions{})
	groups := make([]groupedQuery, 9)
	for i := range groups {
		groups[i] = groupedQuery{url: wsTestURL(relay), authors: []nostr.PubKey{seed}}
	}
	results, _ := source.runGroups(context.Background(), groups, nostr.KindFollowList, newOperatorClient())
	retained := 0
	limited := false
	for _, result := range results {
		for _, raw := range result.raws {
			retained += len(raw)
		}
		if result.err != nil && strings.Contains(result.err.Error(), "aggregate byte budget") {
			limited = true
		}
	}
	if retained > maxRelayBatchBytes || !limited {
		t.Fatalf("aggregate budget not enforced: retained=%d, limited=%v", retained, limited)
	}
}
