package reputation_test

import (
	"context"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"fiatjaf.com/nostr"

	"github.com/lessucettes/adresu-plugin/pkg/adresu-kit/reputation"
)

func pubKey(b byte) nostr.PubKey {
	var key nostr.PubKey
	key[0] = b
	return key
}

func eventID(b byte) nostr.ID {
	var id nostr.ID
	id[0] = b
	return id
}

func followList(author byte, createdAt int64, id byte, follows ...byte) reputation.FollowList {
	list := reputation.FollowList{
		Author:    pubKey(author),
		EventID:   eventID(id),
		CreatedAt: nostr.Timestamp(createdAt),
		Follows:   make([]nostr.PubKey, 0, len(follows)),
	}
	for _, follow := range follows {
		list.Follows = append(list.Follows, pubKey(follow))
	}
	return list
}

func scoreOf(t *testing.T, result *reputation.Result, key nostr.PubKey) reputation.Score {
	t.Helper()
	score, ok := result.Scores[key]
	if !ok {
		t.Fatalf("score for %s is missing", key.Hex())
	}
	return score
}

func assertClose(t *testing.T, name string, got, want float64) {
	t.Helper()
	if math.Abs(got-want) > 1e-9 {
		t.Errorf("%s = %.12f, want %.12f", name, got, want)
	}
}

func assertMass(t *testing.T, result *reputation.Result) {
	t.Helper()
	var trustRank float64
	for _, score := range result.Scores {
		trustRank += score.TrustRank
	}
	if math.Abs(trustRank-1) > 1e-12 {
		t.Errorf("trustrank mass = %.15f, want 1", trustRank)
	}
}

func TestCalculateKnownGraphs(t *testing.T) {
	opts := reputation.DefaultOptions()
	damping := opts.Damping

	t.Run("star", func(t *testing.T) {
		lists := []reputation.FollowList{
			followList('a', 100, 1, 'b', 'c'),
			followList('b', 100, 2, 'a'),
			followList('c', 100, 3, 'a'),
		}
		result, err := reputation.Calculate(context.Background(), lists, []nostr.PubKey{pubKey('a')}, opts)
		if err != nil {
			t.Fatalf("Calculate: %v", err)
		}
		if result.Nodes != 3 || result.Edges != 4 {
			t.Fatalf("graph = %d nodes, %d edges, want 3 nodes, 4 edges", result.Nodes, result.Edges)
		}

		centerTR := (1 - damping) / (1 - damping*damping)
		leafTR := damping * centerTR / 2

		assertClose(t, "trustrank(center)", scoreOf(t, result, pubKey('a')).TrustRank, centerTR)
		assertClose(t, "trustrank(leaf)", scoreOf(t, result, pubKey('b')).TrustRank, leafTR)
		assertMass(t, result)
	})

	t.Run("cycle", func(t *testing.T) {
		lists := []reputation.FollowList{
			followList('a', 100, 1, 'b'),
			followList('b', 100, 2, 'c'),
			followList('c', 100, 3, 'a'),
		}
		result, err := reputation.Calculate(context.Background(), lists, []nostr.PubKey{pubKey('a')}, opts)
		if err != nil {
			t.Fatalf("Calculate: %v", err)
		}

		seedTR := (1 - damping) / (1 - math.Pow(damping, 3))
		assertClose(t, "trustrank(seed)", scoreOf(t, result, pubKey('a')).TrustRank, seedTR)
		assertClose(t, "trustrank(next)", scoreOf(t, result, pubKey('b')).TrustRank, damping*seedTR)
		assertClose(t, "trustrank(last)", scoreOf(t, result, pubKey('c')).TrustRank, damping*damping*seedTR)
		assertMass(t, result)
	})
}

func TestCalculateMassWithDanglingNodes(t *testing.T) {
	opts := reputation.DefaultOptions()
	lists := []reputation.FollowList{
		followList('a', 100, 1, 'b'),
		followList('b', 100, 2, 'c'),
	}
	result, err := reputation.Calculate(context.Background(), lists, []nostr.PubKey{pubKey('a')}, opts)
	if err != nil {
		t.Fatalf("Calculate: %v", err)
	}
	if result.Nodes != 3 || result.Edges != 2 {
		t.Fatalf("graph = %d nodes, %d edges, want 3 nodes, 2 edges", result.Nodes, result.Edges)
	}
	assertMass(t, result)

	// A chain whose end is dangling behaves like the cycle for the seed: the
	// dangling mass returns to the restart vector.
	seedTR := (1 - opts.Damping) / (1 - math.Pow(opts.Damping, 3))
	assertClose(t, "trustrank(seed)", scoreOf(t, result, pubKey('a')).TrustRank, seedTR)
	assertClose(t, "trustrank(middle)", scoreOf(t, result, pubKey('b')).TrustRank, opts.Damping*seedTR)
	assertClose(t, "trustrank(dangling)", scoreOf(t, result, pubKey('c')).TrustRank, opts.Damping*opts.Damping*seedTR)
}

func TestDisconnectedSybilComponentHasZeroTrust(t *testing.T) {
	opts := reputation.DefaultOptions()
	lists := []reputation.FollowList{
		followList('a', 100, 1, 'b'),
		followList('x', 100, 2, 'y'),
		followList('y', 100, 3, 'x'),
	}
	result, err := reputation.Calculate(context.Background(), lists, []nostr.PubKey{pubKey('a')}, opts)
	if err != nil {
		t.Fatalf("Calculate: %v", err)
	}
	if result.Nodes != 4 || result.Edges != 3 {
		t.Fatalf("graph = %d nodes, %d edges, want 4 nodes, 3 edges", result.Nodes, result.Edges)
	}
	if scoreOf(t, result, pubKey('b')).TrustRank <= 0 {
		t.Error("reachable node has zero trustrank")
	}
	for _, key := range []byte{'x', 'y'} {
		score := scoreOf(t, result, pubKey(key))
		if score.TrustRank != 0 {
			t.Errorf("sybil %c trustrank = %v, want exactly 0", key, score.TrustRank)
		}
	}
	assertMass(t, result)
}

func TestStationaryTrustIgnoresDisconnectedComponent(t *testing.T) {
	opts := reputation.DefaultOptions()
	opts.MaxIterations = 1
	lists := []reputation.FollowList{
		followList('a', 100, 1),
		followList('x', 100, 2, 'y'),
		followList('y', 100, 3, 'x'),
	}
	// All trust stays at the dangling seed. An unrelated component must not
	// require extra iterations or prevent this complete result from publishing.
	result, err := reputation.Calculate(context.Background(), lists, []nostr.PubKey{pubKey('a')}, opts)
	if err != nil {
		t.Fatalf("stationary trust failed to converge in one iteration: %v", err)
	}
	assertClose(t, "seed trust", scoreOf(t, result, pubKey('a')).TrustRank, 1)
	for _, key := range []byte{'x', 'y'} {
		if trust := scoreOf(t, result, pubKey(key)).TrustRank; trust != 0 {
			t.Errorf("disconnected node %c trust = %v, want 0", key, trust)
		}
	}
}

func TestSeedFairnessAndDedup(t *testing.T) {
	opts := reputation.DefaultOptions()
	seeds := []nostr.PubKey{pubKey('a'), pubKey('a'), pubKey('b')}
	result, err := reputation.Calculate(context.Background(), nil, seeds, opts)
	if err != nil {
		t.Fatalf("Calculate: %v", err)
	}
	if result.Nodes != 2 || result.Edges != 0 {
		t.Fatalf("graph = %d nodes, %d edges, want 2 nodes, 0 edges", result.Nodes, result.Edges)
	}
	for _, key := range []byte{'a', 'b'} {
		score := scoreOf(t, result, pubKey(key))
		assertClose(t, "trustrank", score.TrustRank, 0.5)
	}

	reversed, err := reputation.Calculate(context.Background(), nil, []nostr.PubKey{pubKey('b'), pubKey('a')}, opts)
	if err != nil {
		t.Fatalf("Calculate with reversed seeds: %v", err)
	}
	if !reflect.DeepEqual(result, reversed) {
		t.Errorf("seed order changed the result: %+v != %+v", result, reversed)
	}
}

func TestZeroSeedsAreIgnored(t *testing.T) {
	opts := reputation.DefaultOptions()
	result, err := reputation.Calculate(context.Background(), nil, []nostr.PubKey{{}, pubKey('a')}, opts)
	if err != nil {
		t.Fatalf("Calculate: %v", err)
	}
	if result.Nodes != 1 {
		t.Fatalf("nodes = %d, want 1", result.Nodes)
	}
	score := scoreOf(t, result, pubKey('a'))
	assertClose(t, "trustrank", score.TrustRank, 1)
	if _, ok := result.Scores[nostr.PubKey{}]; ok {
		t.Error("zero pubkey became a node")
	}
}

func TestNoValidSeedFails(t *testing.T) {
	opts := reputation.DefaultOptions()
	for _, seeds := range [][]nostr.PubKey{nil, {}, {{}}, {{}, {}}} {
		result, err := reputation.Calculate(context.Background(), nil, seeds, opts)
		if err == nil {
			t.Errorf("seeds %v: expected error", seeds)
		}
		if result != nil {
			t.Errorf("seeds %v: result = %+v, want nil", seeds, result)
		}
	}
}

func TestInvalidOptions(t *testing.T) {
	seeds := []nostr.PubKey{pubKey('a')}
	tests := []struct {
		name string
		opts reputation.Options
	}{
		{"damping NaN", reputation.Options{Damping: math.NaN(), Tolerance: 1e-6, MaxIterations: 10}},
		{"damping +Inf", reputation.Options{Damping: math.Inf(1), Tolerance: 1e-6, MaxIterations: 10}},
		{"damping -Inf", reputation.Options{Damping: math.Inf(-1), Tolerance: 1e-6, MaxIterations: 10}},
		{"damping zero", reputation.Options{Damping: 0, Tolerance: 1e-6, MaxIterations: 10}},
		{"damping one", reputation.Options{Damping: 1, Tolerance: 1e-6, MaxIterations: 10}},
		{"damping negative", reputation.Options{Damping: -0.5, Tolerance: 1e-6, MaxIterations: 10}},
		{"tolerance NaN", reputation.Options{Damping: 0.85, Tolerance: math.NaN(), MaxIterations: 10}},
		{"tolerance +Inf", reputation.Options{Damping: 0.85, Tolerance: math.Inf(1), MaxIterations: 10}},
		{"tolerance zero", reputation.Options{Damping: 0.85, Tolerance: 0, MaxIterations: 10}},
		{"tolerance negative", reputation.Options{Damping: 0.85, Tolerance: -1e-6, MaxIterations: 10}},
		{"iterations zero", reputation.Options{Damping: 0.85, Tolerance: 1e-6, MaxIterations: 0}},
		{"iterations negative", reputation.Options{Damping: 0.85, Tolerance: 1e-6, MaxIterations: -3}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := reputation.Calculate(context.Background(), nil, seeds, test.opts)
			if err == nil {
				t.Fatal("expected error")
			}
			if result != nil {
				t.Fatalf("result = %+v, want nil", result)
			}
		})
	}
}

func TestNonConvergenceReturnsError(t *testing.T) {
	opts := reputation.Options{Damping: 0.99, Tolerance: 1e-15, MaxIterations: 1}
	lists := []reputation.FollowList{
		followList('a', 100, 1, 'b'),
		followList('b', 100, 2, 'a'),
	}
	result, err := reputation.Calculate(context.Background(), lists, []nostr.PubKey{pubKey('a')}, opts)
	if err == nil {
		t.Fatal("expected non-convergence error")
	}
	if !strings.Contains(err.Error(), "did not converge") {
		t.Errorf("error = %q, want convergence failure", err)
	}
	if !strings.Contains(err.Error(), "trustrank") {
		t.Errorf("error = %q, want trustrank failure", err)
	}
	if result != nil {
		t.Fatalf("result = %+v, want nil", result)
	}
}

func TestCancellation(t *testing.T) {
	opts := reputation.DefaultOptions()
	lists := []reputation.FollowList{
		followList('a', 100, 1, 'b'),
		followList('b', 100, 2, 'c'),
		followList('c', 100, 3, 'a'),
	}
	seeds := []nostr.PubKey{pubKey('a')}

	t.Run("before build", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		result, err := reputation.Calculate(ctx, lists, seeds, opts)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want context.Canceled", err)
		}
		if result != nil {
			t.Fatalf("result = %+v, want nil", result)
		}
	})

	t.Run("during build", func(t *testing.T) {
		many := make([]reputation.FollowList, 4096)
		for i := range many {
			many[i] = followList('a', int64(i), byte(i))
		}
		ctx := &stepContext{cancelAfter: 3}
		result, err := reputation.Calculate(ctx, many, seeds, opts)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want context.Canceled", err)
		}
		if result != nil {
			t.Fatalf("result = %+v, want nil", result)
		}
	})

	t.Run("during iteration", func(t *testing.T) {
		ctx := &stepContext{cancelAfter: 32}
		opts := reputation.Options{Damping: 0.85, Tolerance: 1e-30, MaxIterations: 10000}
		result, err := reputation.Calculate(ctx, lists, seeds, opts)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want context.Canceled", err)
		}
		if result != nil {
			t.Fatalf("result = %+v, want nil", result)
		}
	})
}

// stepContext cancels deterministically after a fixed number of Err calls.
type stepContext struct {
	calls       int
	cancelAfter int
}

func (c *stepContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (c *stepContext) Done() <-chan struct{}       { return nil }
func (c *stepContext) Value(any) any               { return nil }
func (c *stepContext) Err() error {
	c.calls++
	if c.calls >= c.cancelAfter {
		return context.Canceled
	}
	return nil
}

func TestDeterministicResults(t *testing.T) {
	opts := reputation.DefaultOptions()
	seeds := []nostr.PubKey{pubKey('d'), pubKey('a')}
	lists := []reputation.FollowList{
		followList('a', 100, 1, 'b', 'c', 'b', 'a'),
		followList('b', 100, 2, 'a', 'c'),
		followList('c', 100, 3, 'd'),
		followList('d', 100, 4),
		followList('a', 90, 5, 'd'),
	}
	first, err := reputation.Calculate(context.Background(), lists, seeds, opts)
	if err != nil {
		t.Fatalf("Calculate: %v", err)
	}

	reordered := []reputation.FollowList{
		lists[4], lists[3], lists[2], lists[1], lists[0], lists[0],
	}
	reversedSeeds := []nostr.PubKey{pubKey('a'), pubKey('d')}
	for i := 0; i < 5; i++ {
		next, err := reputation.Calculate(context.Background(), reordered, reversedSeeds, opts)
		if err != nil {
			t.Fatalf("Calculate run %d: %v", i, err)
		}
		if !reflect.DeepEqual(first, next) {
			t.Fatalf("run %d differs:\n%+v\n%+v", i, first, next)
		}
	}
}

func TestDefaultOptions(t *testing.T) {
	opts := reputation.DefaultOptions()
	if opts.Damping <= 0 || opts.Damping >= 1 {
		t.Errorf("damping = %v, want (0, 1)", opts.Damping)
	}
	if opts.Tolerance <= 0 || math.IsInf(opts.Tolerance, 0) || math.IsNaN(opts.Tolerance) {
		t.Errorf("tolerance = %v, want positive finite", opts.Tolerance)
	}
	if opts.MaxIterations <= 0 {
		t.Errorf("max iterations = %d, want positive", opts.MaxIterations)
	}
}
