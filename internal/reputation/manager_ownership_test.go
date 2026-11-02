package reputation

import (
	"context"
	"testing"

	"fiatjaf.com/nostr"
	"github.com/lessucettes/adresu-plugin/internal/config"
)

func TestManagerOwnsDiscoveryRelayConfiguration(t *testing.T) {
	seed := nostr.KeyOne.Public()
	cfg := testConfig(seed)
	cfg.DiscoverRelays = true
	cfg.DiscoveryRelays = []string{"wss://indexer.example"}
	manager := NewManager(context.Background(), testStore(t))
	t.Cleanup(func() { _ = manager.Close() })
	manager.newSource = func(config.ReputationConfig) Source { return mapSource(followList(seed)) }
	if err := manager.Configure(cfg, true); err != nil {
		t.Fatal(err)
	}
	cfg.DiscoveryRelays[0] = "wss://changed.example"
	if got := manager.current.Load().cfg.DiscoveryRelays[0]; got != "wss://indexer.example" {
		t.Fatalf("worker retained caller-owned discovery slice: %s", got)
	}
}
