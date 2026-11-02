package reputation

import (
	"bytes"
	"context"
	"errors"
	"time"

	"fiatjaf.com/nostr"
	kitrep "github.com/lessucettes/adresu-plugin/pkg/adresu-kit/reputation"
)

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
