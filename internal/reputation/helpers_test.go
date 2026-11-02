package reputation

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"fiatjaf.com/nostr"
	"github.com/lessucettes/adresu-plugin/internal/config"
	"github.com/lessucettes/adresu-plugin/internal/store"
	kitrep "github.com/lessucettes/adresu-plugin/pkg/adresu-kit/reputation"
)

type sourceFunc func(context.Context, []nostr.PubKey) (map[nostr.PubKey]kitrep.FollowList, error)

func (f sourceFunc) Fetch(ctx context.Context, keys []nostr.PubKey) (map[nostr.PubKey]kitrep.FollowList, error) {
	return f(ctx, keys)
}

func testConfig(seed nostr.PubKey) config.ReputationConfig {
	return config.ReputationConfig{
		Seeds: []string{seed.Hex()}, Relays: []string{"wss://configured.example"},
		RefreshInterval: time.Hour, MaxAge: 24 * time.Hour, FetchTimeout: time.Second,
		MaxDepth: 2, MaxNodes: 100, MaxEdges: 1000, BatchSize: 20, MaxFollows: 100,
		MinCoverage: 1, Damping: 0.85, Tolerance: 1e-10, MaxIterations: 300,
	}
}

func testStore(t *testing.T) *store.BadgerStore {
	t.Helper()
	db, err := store.NewBadgerStore(&config.DBConfig{Path: filepath.Join(t.TempDir(), "db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func followList(author nostr.PubKey, targets ...nostr.PubKey) kitrep.FollowList {
	return kitrep.FollowList{Author: author, EventID: nostr.ID{1}, CreatedAt: nostr.Timestamp(time.Now().Unix()),
		FetchedAt: time.Now().UTC(), Follows: targets}
}

func mapSource(lists ...kitrep.FollowList) Source {
	return sourceFunc(func(ctx context.Context, keys []nostr.PubKey) (map[nostr.PubKey]kitrep.FollowList, error) {
		result := make(map[nostr.PubKey]kitrep.FollowList)
		for _, list := range lists {
			for _, pk := range keys {
				if pk == list.Author {
					result[pk] = list
				}
			}
		}
		return result, ctx.Err()
	})
}

func waitReady(t *testing.T, reader kitrep.Reader, pk nostr.PubKey) kitrep.Assessment {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if assessment := reader.Lookup(pk); assessment.Ready {
			return assessment
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatal("reputation snapshot did not become ready")
		}
	}
}
