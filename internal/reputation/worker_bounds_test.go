package reputation

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"fiatjaf.com/nostr"
	"github.com/lessucettes/adresu-plugin/internal/config"
	kitconfig "github.com/lessucettes/adresu-plugin/pkg/adresu-kit/config"
	kitpolicy "github.com/lessucettes/adresu-plugin/pkg/adresu-kit/policy"
	kitrep "github.com/lessucettes/adresu-plugin/pkg/adresu-kit/reputation"
)

func TestRefreshHasAnOverallDeadline(t *testing.T) {
	seed := nostr.KeyOne.Public()
	cfg := testConfig(seed)
	cfg.RefreshInterval = 20 * time.Millisecond
	id, seeds, err := configurationID(cfg)
	if err != nil {
		t.Fatal(err)
	}
	m := NewManager(context.Background(), testStore(t))
	defer m.Close()
	active := &view{id: id, cfg: cfg}
	previous := &kitrep.Snapshot{}
	active.snapshot.Store(previous)
	deadlinePresent := false
	blocked := sourceFunc(func(ctx context.Context, _ []nostr.PubKey) (map[nostr.PubKey]kitrep.FollowList, error) {
		_, deadlinePresent = ctx.Deadline()
		<-ctx.Done()
		return nil, ctx.Err()
	})
	outer, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := m.refresh(outer, active, seeds, blocked); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("refresh did not propagate its deadline: %v", err)
	}
	if !deadlinePresent || outer.Err() != nil {
		t.Fatal("refresh relied on the caller's longer deadline")
	}
	if active.snapshot.Load() != previous {
		t.Fatal("timed out refresh replaced the last good snapshot")
	}
}

func TestStaleOptionalListCountsAsMissing(t *testing.T) {
	seed, target := nostr.KeyOne.Public(), nostr.Generate().Public()
	cfg := testConfig(seed)
	cfg.MinCoverage = 0.5
	db := testStore(t)
	stale := followList(target, nostr.Generate().Public())
	stale.FetchedAt = time.Now().Add(-2 * cfg.MaxAge)
	if err := db.SaveFollowList(context.Background(), stale); err != nil {
		t.Fatal(err)
	}
	lists, coverage, _, err := collect(context.Background(), cfg, []nostr.PubKey{seed}, mapSource(followList(seed, target)), db)
	if err != nil || coverage != 0.5 || len(lists) != 1 || lists[0].Author != seed {
		t.Fatalf("unusable row poisoned a graph meeting min_coverage: %v, coverage=%v, lists=%+v", err, coverage, lists)
	}
}

// Only the worker accesses this store. Avoiding disk I/O lets the real worker
// timers and admission reader share synctest's fake time.
type workerMemoryStore struct {
	list     *kitrep.FollowList
	snapshot *kitrep.Snapshot
}

func (s *workerMemoryStore) LoadFollowList(ctx context.Context, _ nostr.PubKey) (*kitrep.FollowList, error) {
	return s.list, ctx.Err()
}

func (s *workerMemoryStore) SaveFollowList(ctx context.Context, list kitrep.FollowList) error {
	s.list = &list
	return ctx.Err()
}

func (s *workerMemoryStore) LoadReputationSnapshot(ctx context.Context) (*kitrep.Snapshot, error) {
	return s.snapshot, ctx.Err()
}

func (s *workerMemoryStore) SaveReputationSnapshot(ctx context.Context, snapshot *kitrep.Snapshot) error {
	s.snapshot = snapshot
	return ctx.Err()
}

func TestWorkerRefreshesBeforeSnapshotExpiry(t *testing.T) {
	for _, maxAge := range []time.Duration{time.Second, 3 * time.Second} {
		t.Run(maxAge.String(), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				seed := nostr.KeyOne.Public()
				cfg := testConfig(seed)
				cfg.MaxDepth = 1
				cfg.RefreshInterval = time.Second
				cfg.MaxAge = maxAge
				var calls atomic.Int32
				m := NewManager(context.Background(), &workerMemoryStore{})
				defer m.Close()
				m.newSource = func(config.ReputationConfig) Source {
					return sourceFunc(func(ctx context.Context, _ []nostr.PubKey) (map[nostr.PubKey]kitrep.FollowList, error) {
						calls.Add(1)
						list := followList(seed)
						// The event arrives before EOSE, within the refresh budget.
						time.Sleep(100 * time.Millisecond)
						return map[nostr.PubKey]kitrep.FollowList{seed: list}, ctx.Err()
					})
				}
				reader, err := m.Reader(cfg)
				if err != nil {
					t.Fatal(err)
				}
				filter, err := kitpolicy.NewReputationFilter(&kitconfig.ReputationFilterConfig{Enabled: true, Mode: "enforce"}, reader)
				if err != nil {
					t.Fatal(err)
				}
				if err := m.Configure(cfg, true); err != nil {
					t.Fatal(err)
				}
				synctest.Wait()
				time.Sleep(100 * time.Millisecond)
				synctest.Wait()
				unknown := &nostr.Event{Kind: 1, PubKey: nostr.Generate().Public()}
				for elapsed := time.Duration(0); elapsed < 5*time.Second; elapsed += 50 * time.Millisecond {
					result, err := filter.Match(context.Background(), unknown, nil)
					if err != nil || result.Allowed {
						t.Fatalf("healthy worker lost enforcement after %s: %+v, %v", elapsed, result, err)
					}
					if maxAge == 3*time.Second && elapsed == 950*time.Millisecond && calls.Load() != 1 {
						t.Fatalf("worker shortened the normal interval despite sufficient validity: %d calls", calls.Load())
					}
					time.Sleep(50 * time.Millisecond)
					synctest.Wait()
				}
			})
		})
	}
}

func TestWorkerCachedRefreshWaitsWithoutExtendingExpiry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		seed := nostr.KeyOne.Public()
		cfg := testConfig(seed)
		cfg.MaxDepth = 1
		cfg.RefreshInterval = 20 * time.Second
		cfg.MaxAge = 20 * time.Second
		cached := followList(seed)
		cached.FetchedAt = time.Now().Add(-9 * time.Second)
		expires := cached.FetchedAt.Add(cfg.MaxAge)
		m := NewManager(context.Background(), &workerMemoryStore{list: &cached})
		defer m.Close()
		var calls atomic.Int32
		m.newSource = func(config.ReputationConfig) Source {
			return sourceFunc(func(context.Context, []nostr.PubKey) (map[nostr.PubKey]kitrep.FollowList, error) {
				calls.Add(1)
				return nil, nil // Completed query, but only the cache is available.
			})
		}
		reader, err := m.Reader(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := m.Configure(cfg, true); err != nil {
			t.Fatal(err)
		}
		synctest.Wait()
		if !reader.Lookup(seed).Ready {
			t.Fatal("valid cached list did not establish readiness")
		}
		if calls.Load() != 0 {
			t.Fatal("initial fresh-cache pass queried the network")
		}
		time.Sleep(2 * time.Second)
		synctest.Wait()
		// The initial pass reuses fresh cache; only the expiry-reserve pass
		// needs a network query, without extending the original receipt.
		if calls.Load() != 1 {
			t.Fatalf("expected one early query after fresh-cache reuse, got %d calls", calls.Load())
		}
		if snapshot := m.current.Load().snapshot.Load(); !snapshot.ValidUntil.Equal(expires) {
			t.Fatalf("cached refresh extended expiry: got %s, want %s", snapshot.ValidUntil, expires)
		}
		time.Sleep(10 * time.Second)
		synctest.Wait()
		if calls.Load() > 4 {
			t.Fatalf("near-expiry cache caused excessive retries: %d calls", calls.Load())
		}
		if reader.Lookup(seed).Ready {
			t.Fatal("expired cached data continued enforcing reputation")
		}
	})
}
