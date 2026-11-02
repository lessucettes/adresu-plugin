package reputation

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"fiatjaf.com/nostr"
	"github.com/lessucettes/adresu-plugin/internal/config"
	kitrep "github.com/lessucettes/adresu-plugin/pkg/adresu-kit/reputation"
)

// Store is deliberately separate from the plugin's ban/moderation interface.
// Implementations retain signed-event version ordering when saving follow lists.
type Store interface {
	LoadFollowList(context.Context, nostr.PubKey) (*kitrep.FollowList, error)
	SaveFollowList(context.Context, kitrep.FollowList) error
	LoadReputationSnapshot(context.Context) (*kitrep.Snapshot, error)
	SaveReputationSnapshot(context.Context, *kitrep.Snapshot) error
}

func collect(ctx context.Context, cfg config.ReputationConfig, seeds []nostr.PubKey, source Source, store Store) ([]kitrep.FollowList, float64, time.Time, error) {
	frontier := slices.Clone(seeds)
	seen := make(map[nostr.PubKey]bool, len(seeds))
	for _, pk := range seeds {
		seen[pk] = true
	}
	lists := make([]kitrep.FollowList, 0)
	requested, covered, edges := 0, 0, 0
	oldest := time.Now().UTC()
	for depth := 0; depth < cfg.MaxDepth && len(frontier) > 0; depth++ {
		slices.SortFunc(frontier, func(a, b nostr.PubKey) int { return bytes.Compare(a[:], b[:]) })
		var next []nostr.PubKey
		for start := 0; start < len(frontier); start += cfg.BatchSize {
			if err := ctx.Err(); err != nil {
				return nil, 0, time.Time{}, err
			}
			if !time.Now().Before(oldest.Add(cfg.MaxAge)) {
				return nil, 0, time.Time{}, fmt.Errorf("follow graph expired during collection")
			}
			batch := frontier[start:min(start+cfg.BatchSize, len(frontier))]
			cached := make(map[nostr.PubKey]*kitrep.FollowList, len(batch))
			pending := make([]nostr.PubKey, 0, len(batch))
			// Resume completed work on retries without renewing its receipts.
			// Fetch early enough to preserve readiness when max_age is close
			// to refresh_interval, matching the worker's expiry reserve.
			freshFor := min(cfg.RefreshInterval, cfg.MaxAge-refreshBudget(&view{cfg: cfg}))
			now := time.Now()
			for _, pk := range batch {
				list, err := store.LoadFollowList(ctx, pk)
				if err != nil {
					return nil, 0, time.Time{}, fmt.Errorf("load follow list: %w", err)
				}
				cached[pk] = list
				if list == nil || list.FetchedAt.IsZero() || len(list.Follows) > cfg.MaxFollows ||
					list.FetchedAt.After(now.Add(5*time.Minute)) || !now.Before(list.FetchedAt.Add(freshFor)) {
					pending = append(pending, pk)
				}
			}
			var fetched map[nostr.PubKey]kitrep.FollowList
			if len(pending) > 0 {
				var fetchErr error
				fetched, fetchErr = source.Fetch(ctx, pending)
				if fetchErr != nil {
					slog.Debug("Reputation follow-list query failed; retaining cached lists", "error", fetchErr)
					// No source reached EOSE. Signed events seen before a timeout
					// do not establish the latest list or refresh its observation age.
					fetched = nil
				}
			}
			if err := ctx.Err(); err != nil {
				return nil, 0, time.Time{}, err
			}
			for _, pk := range batch {
				requested++
				list := cached[pk]
				if candidate, ok := fetched[pk]; ok {
					if candidate.Author != pk || len(candidate.Follows) > cfg.MaxFollows {
						return nil, 0, time.Time{}, fmt.Errorf("follow-list source violated its bounds")
					}
					if err := store.SaveFollowList(ctx, candidate); err != nil {
						return nil, 0, time.Time{}, fmt.Errorf("save follow list: %w", err)
					}
					// Saving can retain a newer version or the winning equal-time
					// event. Always use the store's result, not the candidate.
					var err error
					list, err = store.LoadFollowList(ctx, pk)
					if err != nil {
						return nil, 0, time.Time{}, fmt.Errorf("load follow list: %w", err)
					}
				}
				if list == nil {
					continue // Absence must not erase a previously known adjacency list.
				}
				if list.FetchedAt.IsZero() || time.Since(list.FetchedAt) > cfg.MaxAge || list.FetchedAt.After(time.Now().Add(5*time.Minute)) {
					continue // An unusable row counts as missing, never as an empty list.
				}
				if len(list.Follows) > cfg.MaxFollows {
					continue
				}
				covered++
				if list.FetchedAt.Before(oldest) {
					oldest = list.FetchedAt
				}
				edges += len(list.Follows)
				if edges > cfg.MaxEdges {
					return nil, 0, time.Time{}, fmt.Errorf("follow graph exceeds max_edges")
				}
				for _, target := range list.Follows {
					if !seen[target] {
						seen[target] = true
						next = append(next, target)
						if len(seen) > cfg.MaxNodes {
							return nil, 0, time.Time{}, fmt.Errorf("follow graph exceeds max_nodes")
						}
					}
				}
				lists = append(lists, *list)
			}
		}
		frontier = next
	}
	coverage := 0.0
	if requested > 0 {
		coverage = float64(covered) / float64(requested)
	}
	if coverage < cfg.MinCoverage {
		return nil, coverage, time.Time{}, fmt.Errorf("follow-list coverage %.3f is below required %.3f", coverage, cfg.MinCoverage)
	}
	return lists, coverage, oldest.Add(cfg.MaxAge), nil
}
