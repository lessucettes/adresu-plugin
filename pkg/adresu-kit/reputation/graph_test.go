package reputation_test

import (
	"context"
	"testing"

	"fiatjaf.com/nostr"

	"github.com/lessucettes/adresu-plugin/pkg/adresu-kit/reputation"
)

func TestLatestFollowListWins(t *testing.T) {
	lists := []reputation.FollowList{
		followList('a', 100, 1, 'b'),
		followList('a', 200, 2, 'c'),
	}
	result, err := reputation.Calculate(context.Background(), lists, []nostr.PubKey{pubKey('a')}, reputation.DefaultOptions())
	if err != nil {
		t.Fatalf("Calculate: %v", err)
	}
	if result.Nodes != 2 || result.Edges != 1 {
		t.Fatalf("graph = %d nodes, %d edges, want 2 nodes, 1 edge", result.Nodes, result.Edges)
	}
	if _, ok := result.Scores[pubKey('c')]; !ok {
		t.Error("follow target of the newest list is missing")
	}
	if _, ok := result.Scores[pubKey('b')]; ok {
		t.Error("follow target of the stale list is present")
	}
}

func TestEqualTimestampLowerIDWins(t *testing.T) {
	lists := []reputation.FollowList{
		followList('a', 100, 0x20, 'b'),
		followList('a', 100, 0x10, 'c'),
	}
	result, err := reputation.Calculate(context.Background(), lists, []nostr.PubKey{pubKey('a')}, reputation.DefaultOptions())
	if err != nil {
		t.Fatalf("Calculate: %v", err)
	}
	if result.Nodes != 2 || result.Edges != 1 {
		t.Fatalf("graph = %d nodes, %d edges, want 2 nodes, 1 edge", result.Nodes, result.Edges)
	}
	if _, ok := result.Scores[pubKey('c')]; !ok {
		t.Error("lower event ID list was not selected")
	}
	if _, ok := result.Scores[pubKey('b')]; ok {
		t.Error("higher event ID list was selected")
	}
}

func TestEmptyLatestListRemovesOlderLinks(t *testing.T) {
	lists := []reputation.FollowList{
		followList('a', 100, 1, 'b'),
		followList('a', 200, 2),
		followList('d', 100, 3),
	}
	result, err := reputation.Calculate(context.Background(), lists, []nostr.PubKey{pubKey('a')}, reputation.DefaultOptions())
	if err != nil {
		t.Fatalf("Calculate: %v", err)
	}
	if result.Nodes != 2 || result.Edges != 0 {
		t.Fatalf("graph = %d nodes, %d edges, want 2 nodes, 0 edges", result.Nodes, result.Edges)
	}
	if _, ok := result.Scores[pubKey('b')]; ok {
		t.Error("stale follow target is present")
	}
	isolated := scoreOf(t, result, pubKey('d'))
	if isolated.PageRank <= 0 {
		t.Error("empty-list author is missing from pagerank")
	}
	if isolated.TrustRank != 0 {
		t.Errorf("isolated author trustrank = %v, want 0", isolated.TrustRank)
	}
}

func TestRepeatedSelfAndZeroFollowsAreDiscarded(t *testing.T) {
	lists := []reputation.FollowList{
		followList('a', 100, 1, 'b', 'b', 'b', 'a'),
	}
	lists[0].Follows = append(lists[0].Follows, nostr.PubKey{})
	result, err := reputation.Calculate(context.Background(), lists, []nostr.PubKey{pubKey('a')}, reputation.DefaultOptions())
	if err != nil {
		t.Fatalf("Calculate: %v", err)
	}
	if result.Nodes != 2 || result.Edges != 1 {
		t.Fatalf("graph = %d nodes, %d edges, want 2 nodes, 1 edge", result.Nodes, result.Edges)
	}
	if _, ok := result.Scores[pubKey('b')]; !ok {
		t.Error("deduplicated follow target is missing")
	}
	if _, ok := result.Scores[nostr.PubKey{}]; ok {
		t.Error("zero follow target became a node")
	}
}

func TestFollowTargetWithoutListIsDangling(t *testing.T) {
	lists := []reputation.FollowList{
		followList('a', 100, 1, 'b'),
	}
	result, err := reputation.Calculate(context.Background(), lists, []nostr.PubKey{pubKey('a')}, reputation.DefaultOptions())
	if err != nil {
		t.Fatalf("Calculate: %v", err)
	}
	if result.Nodes != 2 || result.Edges != 1 {
		t.Fatalf("graph = %d nodes, %d edges, want 2 nodes, 1 edge", result.Nodes, result.Edges)
	}
	if scoreOf(t, result, pubKey('b')).TrustRank <= 0 {
		t.Error("dangling follow target has zero trustrank")
	}
}
