package reputation

import (
	"bytes"
	"sort"

	"fiatjaf.com/nostr"
	kitrep "github.com/lessucettes/adresu-plugin/pkg/adresu-kit/reputation"
)

// selectDiscoveryEndpoints groups authors by write relay and applies the
// per-author and per-fetch caps. Relay URLs are validated again here even
// though the metadata parser already rejected insecure shapes.
func selectDiscoveryEndpoints(metadata map[nostr.PubKey]kitrep.RelayList) ([]groupedQuery, int, int) {
	authors := make([]nostr.PubKey, 0, len(metadata))
	for pk := range metadata {
		authors = append(authors, pk)
	}
	sort.Slice(authors, func(i, j int) bool { return bytes.Compare(authors[i][:], authors[j][:]) < 0 })
	byRelay := make(map[string][]nostr.PubKey)
	selected := make(map[string]struct{})
	skipped := 0
	for _, pk := range authors {
		seen := make(map[string]struct{})
		count := 0
		for _, raw := range metadata[pk].WriteRelays {
			if count >= maxDiscoveryAuthorURLs {
				break
			}
			url, err := validateDiscoveryURL(raw)
			if err != nil {
				skipped++
				continue
			}
			if _, duplicate := seen[url]; duplicate {
				continue
			}
			seen[url] = struct{}{}
			if _, known := selected[url]; !known {
				if len(selected) >= maxDiscoveryEndpoints {
					skipped++
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
	return groups, len(groups), skipped
}
