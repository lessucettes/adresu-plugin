package reputation

import (
	"context"
	"errors"
	"testing"
	"time"

	"fiatjaf.com/nostr"
	kitrep "github.com/lessucettes/adresu-plugin/pkg/adresu-kit/reputation"
)

func TestIncompleteQueriesDoNotRefreshCachedLists(t *testing.T) {
	for _, cached := range []bool{false, true} {
		t.Run(map[bool]string{false: "cold", true: "cached"}[cached], func(t *testing.T) {
			ctx := context.Background()
			seed, target := nostr.KeyOne.Public(), nostr.Generate().Public()
			cfg := testConfig(seed)
			cfg.MaxDepth = 1
			db := testStore(t)
			old := followList(seed, target)
			old.FetchedAt = time.Now().Add(-cfg.MaxAge / 2)
			if cached {
				if err := db.SaveFollowList(ctx, old); err != nil {
					t.Fatal(err)
				}
			}
			candidate := followList(seed)
			candidate.CreatedAt = old.CreatedAt + 1
			incomplete := sourceFunc(func(context.Context, []nostr.PubKey) (map[nostr.PubKey]kitrep.FollowList, error) {
				return map[nostr.PubKey]kitrep.FollowList{seed: candidate}, errors.New("connection closed before EOSE")
			})
			lists, _, validUntil, err := collect(ctx, cfg, []nostr.PubKey{seed}, incomplete, db)
			if !cached {
				if err == nil {
					t.Fatal("partial query established cold-start graph readiness")
				}
				stored, loadErr := db.LoadFollowList(ctx, seed)
				if loadErr != nil || stored != nil {
					t.Fatalf("partial query entered fresh cache: %+v, %v", stored, loadErr)
				}
				return
			}
			if err != nil || len(lists) != 1 || len(lists[0].Follows) != 1 || lists[0].Follows[0] != target {
				t.Fatalf("partial query replaced cached adjacency: %+v, %v", lists, err)
			}
			if !validUntil.Equal(old.FetchedAt.Add(cfg.MaxAge)) {
				t.Fatal("partial query extended fallback validity")
			}
		})
	}
}
