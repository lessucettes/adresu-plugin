package reputation

import (
	"bytes"
	"context"
	"slices"

	"fiatjaf.com/nostr"
)

// contextCheckInterval bounds how many items are processed between
// cancellation checks.
const contextCheckInterval = 1024

// graph is a directed follow graph in compressed sparse row form. nodes is
// sorted and unique; the outgoing targets of node i are
// targets[offsets[i]:offsets[i+1]].
type graph struct {
	nodes   []nostr.PubKey
	offsets []int
	targets []int
	seeds   []int
}

func checkContext(ctx context.Context) error {
	return ctx.Err()
}

// buildGraph keeps the newest follow list per author, then builds a
// deterministic graph containing every seed, every surviving author and every
// nonzero follow target. Self-links and duplicate links are discarded.
func buildGraph(ctx context.Context, lists []FollowList, seeds []nostr.PubKey) (*graph, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}

	latest := make(map[nostr.PubKey]FollowList, len(lists))
	for i, list := range lists {
		if i%contextCheckInterval == 0 {
			if err := checkContext(ctx); err != nil {
				return nil, err
			}
		}
		if list.Author == (nostr.PubKey{}) {
			continue
		}
		if current, ok := latest[list.Author]; !ok || newerList(list, current) {
			latest[list.Author] = list
		}
	}

	nodes := make(map[nostr.PubKey]struct{}, len(latest)+len(seeds))
	for author := range latest {
		nodes[author] = struct{}{}
	}
	for _, seed := range seeds {
		if seed != (nostr.PubKey{}) {
			nodes[seed] = struct{}{}
		}
	}

	followsSeen := 0
	for _, list := range latest {
		for _, follow := range list.Follows {
			if followsSeen%contextCheckInterval == 0 {
				if err := checkContext(ctx); err != nil {
					return nil, err
				}
			}
			followsSeen++
			if follow != (nostr.PubKey{}) {
				nodes[follow] = struct{}{}
			}
		}
	}

	nodeList := make([]nostr.PubKey, 0, len(nodes))
	for key := range nodes {
		nodeList = append(nodeList, key)
	}
	slices.SortFunc(nodeList, comparePubKeys)

	index := make(map[nostr.PubKey]int, len(nodeList))
	for i, key := range nodeList {
		index[key] = i
	}

	g := &graph{
		nodes:   nodeList,
		offsets: make([]int, len(nodeList)+1),
	}
	for i, key := range nodeList {
		if i%contextCheckInterval == 0 {
			if err := checkContext(ctx); err != nil {
				return nil, err
			}
		}
		g.offsets[i] = len(g.targets)

		list, ok := latest[key]
		if !ok {
			continue
		}
		row := make([]int, 0, len(list.Follows))
		for _, follow := range list.Follows {
			if follow == (nostr.PubKey{}) || follow == key {
				continue
			}
			row = append(row, index[follow])
		}
		slices.Sort(row)
		g.targets = append(g.targets, slices.Compact(row)...)
	}
	g.offsets[len(nodeList)] = len(g.targets)

	seedSet := make(map[int]struct{}, len(seeds))
	for _, seed := range seeds {
		if seed != (nostr.PubKey{}) {
			seedSet[index[seed]] = struct{}{}
		}
	}
	g.seeds = make([]int, 0, len(seedSet))
	for i := range seedSet {
		g.seeds = append(g.seeds, i)
	}
	slices.Sort(g.seeds)

	return g, nil
}

// newerList reports whether candidate should replace current: latest
// created_at wins, and an equal timestamp is broken by the lower event ID.
func newerList(candidate, current FollowList) bool {
	if candidate.CreatedAt != current.CreatedAt {
		return candidate.CreatedAt > current.CreatedAt
	}
	return bytes.Compare(candidate.EventID[:], current.EventID[:]) < 0
}

func comparePubKeys(a, b nostr.PubKey) int {
	return bytes.Compare(a[:], b[:])
}
