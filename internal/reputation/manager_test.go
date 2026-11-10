package reputation

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"fiatjaf.com/nostr"
	"github.com/lessucettes/adresu-plugin/internal/config"
	kitrep "github.com/lessucettes/adresu-plugin/pkg/adresu-kit/reputation"
)

func TestManagerReloadRestartAndScopedReaders(t *testing.T) {
	seed, target := nostr.KeyOne.Public(), nostr.Generate().Public()
	cfg := testConfig(seed)
	db := testStore(t)
	m := NewManager(context.Background(), db)
	t.Cleanup(func() { _ = m.Close() })
	m.newSource = func(config.ReputationConfig) Source {
		return mapSource(followList(seed, target), followList(target))
	}
	reader, err := m.Reader(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if reader.Lookup(target).Ready {
		t.Fatal("uninitialized graph claimed readiness")
	}
	if err := m.Configure(cfg, true); err != nil {
		t.Fatal(err)
	}
	if assessment := waitReady(t, reader, target); !assessment.Known || assessment.Score.TrustRank <= 0 {
		t.Fatalf("missing target score: %+v", assessment)
	}
	oldView := m.current.Load()
	if err := m.Configure(cfg, true); err != nil || m.current.Load() != oldView {
		t.Fatal("policy-only reload replaced the collector")
	}
	if reader.Lookup(nostr.Generate().Public()).Known {
		t.Fatal("unknown author manufactured a score")
	}
	if err := m.Close(); err != nil {
		t.Fatal(err)
	}
	// A restart restores the durable snapshot without waiting for network I/O.
	restarted := NewManager(context.Background(), db)
	t.Cleanup(func() { _ = restarted.Close() })
	restarted.newSource = func(config.ReputationConfig) Source {
		return sourceFunc(func(ctx context.Context, _ []nostr.PubKey) (map[nostr.PubKey]kitrep.FollowList, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		})
	}
	restoredReader, err := restarted.Reader(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Configure(cfg, true); err != nil {
		t.Fatal(err)
	}
	if !waitReady(t, restoredReader, target).Known {
		t.Fatal("persisted scores not restored")
	}
	changed := cfg
	changed.Relays = []string{"wss://other.example"}
	if err := restarted.Configure(changed, true); err != nil {
		t.Fatal(err)
	}
	if restoredReader.Lookup(target).Ready {
		t.Fatal("retired reader consumed a different graph configuration")
	}
	if err := restarted.Configure(changed, false); err != nil {
		t.Fatal(err)
	}
	if restarted.current.Load() != nil {
		t.Fatal("disabled collector kept running")
	}
}

func TestReaderExpiryAndConcurrentReads(t *testing.T) {
	seed := nostr.KeyOne.Public()
	cfg := testConfig(seed)
	id, _, err := configurationID(cfg)
	if err != nil {
		t.Fatal(err)
	}
	m := NewManager(context.Background(), testStore(t))
	defer m.Close()
	active := &view{id: id, cfg: cfg}
	m.current.Store(active)
	reader := scopedReader{manager: m, id: id}
	now := time.Now()
	active.snapshot.Store(&kitrep.Snapshot{CalculatedAt: now, ValidUntil: now.Add(time.Hour), Scores: map[nostr.PubKey]kitrep.Score{seed: {TrustRank: 1}}})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Go(func() {
			for j := 0; j < 100; j++ {
				if !reader.Lookup(seed).Ready {
					t.Error("ready immutable snapshot became unavailable")
				}
			}
		})
	}
	wg.Wait()
	active.snapshot.Store(&kitrep.Snapshot{CalculatedAt: now, ValidUntil: now.Add(-time.Second)})
	if reader.Lookup(seed).Ready {
		t.Fatal("expired snapshot still enforced")
	}
}

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

type failedSnapshotStore struct{ Store }

func (s failedSnapshotStore) SaveReputationSnapshot(context.Context, *kitrep.Snapshot) error {
	return errors.New("simulated disk failure")
}

func TestPersistenceFailureDoesNotPublish(t *testing.T) {
	seed := nostr.KeyOne.Public()
	cfg := testConfig(seed)
	cfg.MaxDepth = 1
	id, seeds, err := configurationID(cfg)
	if err != nil {
		t.Fatal(err)
	}
	m := NewManager(context.Background(), failedSnapshotStore{testStore(t)})
	defer m.Close()
	active := &view{id: id, cfg: cfg}
	if err := m.refresh(context.Background(), active, seeds, mapSource(followList(seed))); err == nil {
		t.Fatal("disk failure ignored")
	}
	if active.snapshot.Load() != nil {
		t.Fatal("non-durable result published")
	}
}
