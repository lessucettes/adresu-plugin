package reputation

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"fiatjaf.com/nostr"
	"github.com/lessucettes/adresu-plugin/internal/config"
	kitrep "github.com/lessucettes/adresu-plugin/pkg/adresu-kit/reputation"
)

// Source returns only verified lists. A missing author is not an empty list.
// An error means no source completed the batch. Partial results must not
// establish readiness or refresh cache age without a completed query.
type Source interface {
	Fetch(context.Context, []nostr.PubKey) (map[nostr.PubKey]kitrep.FollowList, error)
}

type relaySource struct{ cfg config.ReputationConfig }

type relayResult struct {
	lists map[nostr.PubKey]kitrep.FollowList
	err   error
}

func (s relaySource) Fetch(ctx context.Context, authors []nostr.PubKey) (map[nostr.PubKey]kitrep.FollowList, error) {
	results := make(chan relayResult, len(s.cfg.Relays))
	var wg sync.WaitGroup
	// Configuration caps relay count; each batch has a bounded request lifetime.
	for _, url := range s.cfg.Relays {
		wg.Add(1)
		go func() {
			defer wg.Done()
			lists, err := s.fetchRelay(ctx, url, authors)
			results <- relayResult{lists, err}
		}()
	}
	wg.Wait()
	close(results)
	merged := make(map[nostr.PubKey]kitrep.FollowList)
	var failures []error
	completed := false
	for result := range results {
		if result.err != nil {
			failures = append(failures, result.err)
			continue
		}
		completed = true
		for pk, list := range result.lists {
			previous, found := merged[pk]
			if !found || newer(list, previous) {
				merged[pk] = list
			}
		}
	}
	if !completed {
		return merged, fmt.Errorf("no relay completed the follow-list query: %w", errors.Join(failures...))
	}
	return merged, nil
}

func newer(a, b kitrep.FollowList) bool {
	return a.CreatedAt > b.CreatedAt ||
		(a.CreatedAt == b.CreatedAt && bytes.Compare(a.EventID[:], b.EventID[:]) < 0)
}

// fetchRelay uses the generic NIP-42 transport and accepts a relay's events
// only after its completed EOSE. Each raw event still goes through full
// canonical signature verification before entering the follow-list map.
func (s relaySource) fetchRelay(ctx context.Context, url string, authors []nostr.PubKey) (map[nostr.PubKey]kitrep.FollowList, error) {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.FetchTimeout)
	defer cancel()
	events, err := queryRelay(ctx, url, authors, nostr.KindFollowList, newOperatorClient(), nil)
	if err != nil {
		return nil, err
	}
	lists := make(map[nostr.PubKey]kitrep.FollowList)
	now := time.Now()
	for _, raw := range events {
		list, err := kitrep.ParseFollowList(ctx, raw, s.cfg.MaxFollows, now)
		if err != nil {
			continue
		}
		previous, found := lists[list.Author]
		if !found || newer(list, previous) {
			lists[list.Author] = list
		}
	}
	return lists, nil
}
