package reputation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"sync"
	"time"

	"fiatjaf.com/nostr"
	"github.com/lessucettes/adresu-plugin/internal/config"
	kitrep "github.com/lessucettes/adresu-plugin/pkg/adresu-kit/reputation"
)

const (
	maxDiscoveryConcurrency = 8
	maxDiscoveryEndpoints   = 64
	maxDiscoveryAuthorURLs  = 4
)

type discoverySource struct {
	cfg       config.ReputationConfig
	fixed     relaySource
	bootstrap *http.Client
	public    *http.Client
	cache     *discoveryCache
	sem       chan struct{}
}

type groupedQuery struct {
	url     string
	authors []nostr.PubKey
}

type groupedResult struct {
	raws []json.RawMessage
	err  error
}

// newDiscoverySource wraps the fixed relay source with an opt-in NIP-65
// fallback. The fixed source always runs first; only authors it could not
// produce are looked up through the configured discovery indexers.
func newDiscoverySource(cfg config.ReputationConfig) *discoverySource {
	return newDiscoverySourceWithOptions(cfg, discoveryDialOptions{})
}

func newDiscoverySourceWithOptions(cfg config.ReputationConfig, opts discoveryDialOptions) *discoverySource {
	return &discoverySource{
		cfg:       cfg,
		fixed:     relaySource{cfg: cfg},
		bootstrap: newOperatorClient(),
		public:    newDiscoveryClient(opts),
		cache:     newDiscoveryCache(cfg.MaxNodes),
		sem:       make(chan struct{}, maxDiscoveryConcurrency),
	}
}

func (s *discoverySource) Fetch(ctx context.Context, authors []nostr.PubKey) (map[nostr.PubKey]kitrep.FollowList, error) {
	if len(authors) == 0 {
		return map[nostr.PubKey]kitrep.FollowList{}, nil
	}
	fixed, fixedErr := s.fixed.Fetch(ctx, authors)
	missing := make([]nostr.PubKey, 0, len(authors))
	for _, pk := range authors {
		if _, found := fixed[pk]; !found {
			missing = append(missing, pk)
		}
	}
	if len(missing) == 0 {
		return fixed, nil
	}
	discovered, completed, discoverErr := s.discover(ctx, missing)
	for pk, list := range discovered {
		previous, found := fixed[pk]
		if !found || newer(list, previous) {
			fixed[pk] = list
		}
	}
	if fixedErr == nil || completed > 0 {
		return fixed, nil
	}
	return fixed, errors.Join(fixedErr, discoverErr)
}

func (s *discoverySource) discover(ctx context.Context, authors []nostr.PubKey) (map[nostr.PubKey]kitrep.FollowList, int, error) {
	now := time.Now()
	metadata := make(map[nostr.PubKey]kitrep.RelayList)
	var lookup []nostr.PubKey
	for _, pk := range authors {
		if cached, ok := s.cache.cached(pk, now); ok {
			metadata[pk] = cached
			continue
		}
		// Keep the last verified metadata as a baseline; a failed refresh
		// must not discard usable relay URLs.
		if stale, ok := s.cache.stale(pk); ok {
			metadata[pk] = stale
		}
		if !s.cache.backoff(pk, now) {
			lookup = append(lookup, pk)
		}
	}
	var errs []error
	if len(lookup) > 0 {
		found, complete, err := s.fetchMetadata(ctx, lookup, now)
		if err != nil {
			errs = append(errs, err)
		}
		for pk, list := range found {
			if previous, ok := metadata[pk]; !ok || newerRelayMetadata(list, previous) {
				metadata[pk] = list
			}
			s.cache.putMetadata(pk, list, now)
		}
		if complete {
			for _, pk := range lookup {
				if _, ok := found[pk]; !ok {
					// Absence does not revoke previously verified metadata;
					// only a newer signed replacement changes its write relays.
					s.cache.markMissing(pk, now)
				}
			}
		} else {
			for _, pk := range lookup {
				s.cache.markFailed(pk, now)
			}
		}
	}
	// A failed or negative lookup keeps any previously verified metadata.
	groups := selectDiscoveryEndpoints(metadata)
	if len(groups) == 0 {
		return nil, 0, errors.Join(errs...)
	}
	results, completed := s.runGroups(ctx, groups, nostr.KindFollowList, s.public)
	lists := make(map[nostr.PubKey]kitrep.FollowList)
	for i, result := range results {
		if result.err != nil {
			errs = append(errs, result.err)
			continue
		}
		requested := make(map[nostr.PubKey]struct{}, len(groups[i].authors))
		for _, pk := range groups[i].authors {
			requested[pk] = struct{}{}
		}
		for _, raw := range result.raws {
			list, err := kitrep.ParseFollowList(ctx, raw, s.cfg.MaxFollows, now)
			if err != nil {
				continue
			}
			if _, ok := requested[list.Author]; !ok {
				continue
			}
			previous, found := lists[list.Author]
			if !found || newer(list, previous) {
				lists[list.Author] = list
			}
		}
	}
	return lists, completed, errors.Join(errs...)
}

func (s *discoverySource) runGroups(ctx context.Context, groups []groupedQuery, kind nostr.Kind, client *http.Client) ([]groupedResult, int) {
	results := make([]groupedResult, len(groups))
	budget := newRelayByteBudget()
	var wg sync.WaitGroup
	for i := range groups {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			select {
			case s.sem <- struct{}{}:
				defer func() { <-s.sem }()
			case <-ctx.Done():
				results[i].err = ctx.Err()
				return
			}
			if budget.exhausted() {
				results[i].err = errAggregateRelayBudget
				return
			}
			queryCtx, cancel := context.WithTimeout(ctx, s.cfg.FetchTimeout)
			defer cancel()
			results[i].raws, results[i].err = queryRelay(queryCtx, groups[i].url, groups[i].authors, kind, client, budget)
		}(i)
	}
	wg.Wait()
	completed := 0
	for _, result := range results {
		if result.err == nil {
			completed++
		}
	}
	return results, completed
}

// fetchMetadata queries the configured bootstrap indexers for signed kind
// 10002 metadata. The returned completed flag means at least one bootstrap
// relay reached EOSE; only then is an absent author treated as a negative
// result rather than a transient failure.
func (s *discoverySource) fetchMetadata(ctx context.Context, authors []nostr.PubKey, now time.Time) (map[nostr.PubKey]kitrep.RelayList, bool, error) {
	groups := make([]groupedQuery, 0, len(s.cfg.DiscoveryRelays))
	for _, url := range s.cfg.DiscoveryRelays {
		groups = append(groups, groupedQuery{url: url, authors: authors})
	}
	results, completed := s.runGroups(ctx, groups, nostr.KindRelayListMetadata, s.bootstrap)
	requested := make(map[nostr.PubKey]struct{}, len(authors))
	for _, pk := range authors {
		requested[pk] = struct{}{}
	}
	found := make(map[nostr.PubKey]kitrep.RelayList)
	var errs []error
	for _, result := range results {
		if result.err != nil {
			errs = append(errs, result.err)
			continue
		}
		for _, raw := range result.raws {
			list, err := kitrep.ParseRelayList(ctx, raw, now)
			if err != nil {
				continue
			}
			if _, ok := requested[list.Author]; !ok {
				continue
			}
			previous, ok := found[list.Author]
			if !ok || newerRelayMetadata(list, previous) {
				found[list.Author] = list
			}
		}
	}
	return found, completed > 0, errors.Join(errs...)
}

func newerRelayMetadata(a, b kitrep.RelayList) bool {
	return a.CreatedAt > b.CreatedAt ||
		(a.CreatedAt == b.CreatedAt && bytes.Compare(a.EventID[:], b.EventID[:]) < 0)
}

// selectDiscoveryEndpoints groups authors by write relay and applies the
// per-author and per-fetch caps. Relay URLs are validated again here even
// though the metadata parser already rejected insecure shapes.
func selectDiscoveryEndpoints(metadata map[nostr.PubKey]kitrep.RelayList) []groupedQuery {
	authors := make([]nostr.PubKey, 0, len(metadata))
	for pk := range metadata {
		authors = append(authors, pk)
	}
	sort.Slice(authors, func(i, j int) bool { return bytes.Compare(authors[i][:], authors[j][:]) < 0 })
	byRelay := make(map[string][]nostr.PubKey)
	selected := make(map[string]struct{})
	for _, pk := range authors {
		seen := make(map[string]struct{})
		count := 0
		for _, raw := range metadata[pk].WriteRelays {
			if count >= maxDiscoveryAuthorURLs {
				break
			}
			url, err := validateDiscoveryURL(raw)
			if err != nil {
				continue
			}
			if _, duplicate := seen[url]; duplicate {
				continue
			}
			seen[url] = struct{}{}
			if _, known := selected[url]; !known {
				if len(selected) >= maxDiscoveryEndpoints {
					continue
				}
				selected[url] = struct{}{}
			}
			byRelay[url] = append(byRelay[url], pk)
			count++
		}
	}
	urls := make([]string, 0, len(byRelay))
	for url := range byRelay {
		urls = append(urls, url)
	}
	sort.Strings(urls)
	groups := make([]groupedQuery, 0, len(urls))
	for _, url := range urls {
		groups = append(groups, groupedQuery{url: url, authors: byRelay[url]})
	}
	return groups
}
