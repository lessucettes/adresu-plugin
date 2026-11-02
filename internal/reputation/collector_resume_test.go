package reputation

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"fiatjaf.com/nostr"
	kitrep "github.com/lessucettes/adresu-plugin/pkg/adresu-kit/reputation"
)

func TestRefreshResumesCompletedListsWithoutRenewingReceipts(t *testing.T) {
	seed, target := nostr.KeyOne.Public(), nostr.Generate().Public()
	cfg := testConfig(seed)
	cfg.BatchSize = 1
	db := testStore(t)
	m := NewManager(context.Background(), db)
	defer m.Close()
	id, seeds, err := configurationID(cfg)
	if err != nil {
		t.Fatal(err)
	}
	active := &view{id: id, cfg: cfg}
	ctx, cancel := context.WithCancel(context.Background())
	first := sourceFunc(func(ctx context.Context, keys []nostr.PubKey) (map[nostr.PubKey]kitrep.FollowList, error) {
		if slices.Contains(keys, target) {
			cancel()
			return nil, ctx.Err()
		}
		return map[nostr.PubKey]kitrep.FollowList{seed: followList(seed, target)}, nil
	})
	if err := m.refresh(ctx, active, seeds, first); !errors.Is(err, context.Canceled) {
		t.Fatalf("interrupted refresh: %v", err)
	}
	if active.snapshot.Load() != nil {
		t.Fatal("partial crawl was published")
	}
	cached, err := db.LoadFollowList(context.Background(), seed)
	if err != nil || cached == nil {
		t.Fatalf("completed first batch was not cached: %+v, %v", cached, err)
	}
	calls := 0
	resume := sourceFunc(func(_ context.Context, keys []nostr.PubKey) (map[nostr.PubKey]kitrep.FollowList, error) {
		calls++
		if !slices.Equal(keys, []nostr.PubKey{target}) {
			t.Fatalf("fresh completed authors were fetched again: %v", keys)
		}
		return map[nostr.PubKey]kitrep.FollowList{target: followList(target)}, nil
	})
	if err := m.refresh(context.Background(), active, seeds, resume); err != nil {
		t.Fatal(err)
	}
	snapshot := active.snapshot.Load()
	if calls != 1 || snapshot == nil || snapshot.Coverage != 1 || snapshot.Nodes != 2 {
		t.Fatalf("resume did not publish the complete graph: calls=%d, snapshot=%+v", calls, snapshot)
	}
	if !snapshot.ValidUntil.Equal(cached.FetchedAt.Add(cfg.MaxAge)) {
		t.Fatal("cache reuse extended observation validity")
	}
	reloaded, err := db.LoadFollowList(context.Background(), seed)
	if err != nil || !reloaded.FetchedAt.Equal(cached.FetchedAt) {
		t.Fatal("cache reuse renewed the receipt")
	}
	if err := m.refresh(context.Background(), active, seeds, resume); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || !active.snapshot.Load().ValidUntil.Equal(snapshot.ValidUntil) {
		t.Fatal("fully fresh graph triggered an empty query or renewed validity")
	}
}

func TestCollectKeepsStoredWinnerAfterDueRefresh(t *testing.T) {
	for _, tie := range []bool{false, true} {
		t.Run(map[bool]string{false: "older", true: "losing_tie"}[tie], func(t *testing.T) {
			ctx := context.Background()
			seed, target := nostr.KeyOne.Public(), nostr.Generate().Public()
			cfg := testConfig(seed)
			cfg.MaxDepth = 1
			cached := followList(seed, target)
			cached.FetchedAt = time.Now().Add(-cfg.RefreshInterval - time.Second)
			cached.EventID[31] = 1
			candidate := followList(seed)
			candidate.CreatedAt = cached.CreatedAt
			candidate.EventID = cached.EventID
			candidate.EventID[31] = 2
			if !tie {
				candidate.CreatedAt--
			}
			db := testStore(t)
			if err := db.SaveFollowList(ctx, cached); err != nil {
				t.Fatal(err)
			}
			calls := 0
			source := sourceFunc(func(context.Context, []nostr.PubKey) (map[nostr.PubKey]kitrep.FollowList, error) {
				calls++
				return map[nostr.PubKey]kitrep.FollowList{seed: candidate}, nil
			})
			lists, coverage, until, err := collect(ctx, cfg, []nostr.PubKey{seed}, source, db)
			if err != nil || calls != 1 || coverage != 1 || len(lists) != 1 || !slices.Equal(lists[0].Follows, cached.Follows) {
				t.Fatalf("source bypassed the stored winner: lists=%+v coverage=%g calls=%d error=%v", lists, coverage, calls, err)
			}
			if !until.Equal(cached.FetchedAt.Add(cfg.MaxAge)) || !lists[0].FetchedAt.Equal(cached.FetchedAt) {
				t.Fatal("losing candidate renewed the winning receipt")
			}
		})
	}
}

func TestCollectFetchesOnlyDueOrUnusableLists(t *testing.T) {
	ctx := context.Background()
	cfg := testConfig(nostr.KeyOne.Public())
	cfg.MaxDepth = 1
	cfg.MinCoverage = 0.1
	cfg.MaxFollows = 1
	db := testStore(t)
	var keys, due []nostr.PubKey
	for _, state := range []string{"fresh", "due", "missing", "expired", "future", "oversized"} {
		key := nostr.Generate().Public()
		keys = append(keys, key)
		if state != "fresh" {
			due = append(due, key)
		}
		if state == "missing" {
			continue
		}
		list := followList(key)
		switch state {
		case "due":
			list.FetchedAt = time.Now().Add(-cfg.RefreshInterval - time.Second)
		case "expired":
			list.FetchedAt = time.Now().Add(-cfg.MaxAge - time.Second)
		case "future":
			list.FetchedAt = time.Now().Add(6 * time.Minute)
		case "oversized":
			list.Follows = []nostr.PubKey{nostr.Generate().Public(), nostr.Generate().Public()}
		}
		if err := db.SaveFollowList(ctx, list); err != nil {
			t.Fatal(err)
		}
	}
	calls := 0
	source := sourceFunc(func(_ context.Context, pending []nostr.PubKey) (map[nostr.PubKey]kitrep.FollowList, error) {
		calls++
		if len(pending) != len(due) {
			t.Fatalf("requested %d authors, want %d", len(pending), len(due))
		}
		for _, key := range due {
			if !slices.Contains(pending, key) {
				t.Fatal("due or unusable author was not requested")
			}
		}
		return nil, nil
	})
	lists, coverage, _, err := collect(ctx, cfg, keys, source, db)
	if err != nil || calls != 1 || len(lists) != 2 || coverage != 2.0/6 {
		t.Fatalf("cached and missing coverage changed: lists=%d coverage=%g calls=%d error=%v", len(lists), coverage, calls, err)
	}
}
