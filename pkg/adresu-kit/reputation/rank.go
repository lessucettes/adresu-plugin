package reputation

import (
	"context"
	"fmt"
	"math"

	"fiatjaf.com/nostr"
)

const (
	defaultDamping       = 0.85
	defaultTolerance     = 1e-9
	defaultMaxIterations = 200
)

// DefaultOptions returns the standard damping factor and convergence limits.
func DefaultOptions() Options {
	return Options{
		Damping:       defaultDamping,
		Tolerance:     defaultTolerance,
		MaxIterations: defaultMaxIterations,
	}
}

// Calculate builds the local follow graph and ranks it with a seed-restarted
// TrustRank power iteration. It returns an error instead of partial scores
// when a run fails to converge.
func Calculate(ctx context.Context, lists []FollowList, seeds []nostr.PubKey, opts Options) (*Result, error) {
	if err := validateOptions(opts); err != nil {
		return nil, err
	}
	if countUniqueSeeds(seeds) == 0 {
		return nil, fmt.Errorf("reputation: at least one nonzero seed is required")
	}

	g, err := buildGraph(ctx, lists, seeds)
	if err != nil {
		return nil, fmt.Errorf("reputation: build graph: %w", err)
	}

	trustRestart := make([]float64, len(g.nodes))
	for _, seed := range g.seeds {
		trustRestart[seed] = 1 / float64(len(g.seeds))
	}
	trustRank, err := powerIteration(ctx, g, opts, trustRestart)
	if err != nil {
		return nil, fmt.Errorf("reputation: trustrank: %w", err)
	}

	scores := make(map[nostr.PubKey]Score, len(g.nodes))
	for i, key := range g.nodes {
		scores[key] = Score{TrustRank: trustRank[i]}
	}
	return &Result{Scores: scores, Nodes: len(g.nodes), Edges: len(g.targets)}, nil
}

func validateOptions(opts Options) error {
	if math.IsNaN(opts.Damping) || math.IsInf(opts.Damping, 0) || opts.Damping <= 0 || opts.Damping >= 1 {
		return fmt.Errorf("reputation: damping must be finite and in (0, 1), got %v", opts.Damping)
	}
	if math.IsNaN(opts.Tolerance) || math.IsInf(opts.Tolerance, 0) || opts.Tolerance <= 0 {
		return fmt.Errorf("reputation: tolerance must be positive and finite, got %v", opts.Tolerance)
	}
	if opts.MaxIterations <= 0 {
		return fmt.Errorf("reputation: max iterations must be positive, got %d", opts.MaxIterations)
	}
	return nil
}

func countUniqueSeeds(seeds []nostr.PubKey) int {
	unique := make(map[nostr.PubKey]struct{}, len(seeds))
	for _, seed := range seeds {
		if seed != (nostr.PubKey{}) {
			unique[seed] = struct{}{}
		}
	}
	return len(unique)
}

// powerIteration computes TrustRank. restart is a seed-only
// normalized probability vector: the damping loss and dangling mass both
// return to it, so total mass stays at one.
func powerIteration(ctx context.Context, g *graph, opts Options, restart []float64) ([]float64, error) {
	n := len(g.nodes)
	current := append([]float64(nil), restart...)
	next := make([]float64, n)

	for iteration := 0; iteration < opts.MaxIterations; iteration++ {
		if err := checkContext(ctx); err != nil {
			return nil, err
		}

		dangling := 0.0
		for i, mass := range current {
			if g.offsets[i] == g.offsets[i+1] {
				dangling += mass
			}
		}

		for i := 0; i < n; i++ {
			if i%contextCheckInterval == 0 {
				if err := checkContext(ctx); err != nil {
					return nil, err
				}
			}
			start, end := g.offsets[i], g.offsets[i+1]
			if start == end {
				continue
			}
			share := opts.Damping * current[i] / float64(end-start)
			for _, target := range g.targets[start:end] {
				next[target] += share
			}
		}

		returnMass := (1 - opts.Damping + opts.Damping*dangling)
		delta := 0.0
		for i := range next {
			next[i] += returnMass * restart[i]
			delta += math.Abs(next[i] - current[i])
		}

		current, next = next, current
		for i := range next {
			next[i] = 0
		}
		if delta <= opts.Tolerance {
			return current, nil
		}
	}
	return nil, fmt.Errorf("did not converge in %d iterations", opts.MaxIterations)
}
