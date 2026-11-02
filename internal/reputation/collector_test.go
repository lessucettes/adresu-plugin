package reputation

import (
	"context"
	"errors"
	"testing"
	"time"

	"fiatjaf.com/nostr"
	kitrep "github.com/lessucettes/adresu-plugin/pkg/adresu-kit/reputation"
)

func TestCollectReplacementAndMissingLists(t *testing.T) {
	ctx := context.Background()
	seed, a, b := nostr.KeyOne.Public(), nostr.Generate().Public(), nostr.Generate().Public()
	cfg := testConfig(seed)
	cfg.MaxDepth = 1
	db := testStore(t)
	old := followList(seed, a)
	if err := db.SaveFollowList(ctx, old); err != nil {
		t.Fatal(err)
	}
	missing := sourceFunc(func(context.Context, []nostr.PubKey) (map[nostr.PubKey]kitrep.FollowList, error) {
		return nil, errors.New("offline")
	})
	lists, coverage, validUntil, err := collect(ctx, cfg, []nostr.PubKey{seed}, missing, db)
	if err != nil || coverage != 1 || len(lists) != 1 || lists[0].Follows[0] != a {
		t.Fatalf("cached list lost on failure: %v %+v", err, lists)
	}
	if !validUntil.Equal(old.FetchedAt.Add(cfg.MaxAge)) {
		t.Fatal("failed refresh extended cache validity")
	}
	latest := followList(seed, b)
	latest.CreatedAt = old.CreatedAt + 1
	lists, _, _, err = collect(ctx, cfg, []nostr.PubKey{seed}, mapSource(latest), db)
	if err != nil || lists[0].Follows[0] != b {
		t.Fatalf("replacement not applied: %v", err)
	}
	latest.CreatedAt++
	latest.Follows = nil
	lists, _, _, err = collect(ctx, cfg, []nostr.PubKey{seed}, mapSource(latest), db)
	if err != nil || len(lists[0].Follows) != 0 {
		t.Fatalf("empty signed list did not remove edges: %v", err)
	}
}

func TestCollectBoundsAndCoverage(t *testing.T) {
	seed, a, b := nostr.KeyOne.Public(), nostr.Generate().Public(), nostr.Generate().Public()
	for _, name := range []string{"nodes", "edges", "follows", "coverage", "stale"} {
		t.Run(name, func(t *testing.T) {
			cfg := testConfig(seed)
			list := followList(seed, a, b)
			switch name {
			case "nodes":
				cfg.MaxNodes = 2
			case "edges":
				cfg.MaxEdges = 1
			case "follows":
				cfg.MaxFollows = 1
			case "stale":
				list.FetchedAt = time.Now().Add(-2 * cfg.MaxAge)
			}
			_, _, _, err := collect(context.Background(), cfg, []nostr.PubKey{seed}, mapSource(list), testStore(t))
			if err == nil {
				t.Fatal("incomplete or oversized graph accepted")
			}
		})
	}
}

func TestFailedRefreshKeepsPublishedSnapshot(t *testing.T) {
	ctx := context.Background()
	seed, a := nostr.KeyOne.Public(), nostr.Generate().Public()
	cfg := testConfig(seed)
	id, seeds, err := configurationID(cfg)
	if err != nil {
		t.Fatal(err)
	}
	active := &view{id: id, cfg: cfg}
	m := NewManager(ctx, testStore(t))
	defer m.Close()
	if err := m.refresh(ctx, active, seeds, mapSource(followList(seed, a), followList(a))); err != nil {
		t.Fatal(err)
	}
	previous := active.snapshot.Load()
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := m.refresh(cancelled, active, seeds, mapSource()); err == nil {
		t.Fatal("cancelled refresh succeeded")
	}
	if active.snapshot.Load() != previous {
		t.Fatal("failed refresh changed published generation")
	}
}
