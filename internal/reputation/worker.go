package reputation

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"time"

	"fiatjaf.com/nostr"
	"github.com/lessucettes/adresu-plugin/internal/config"
	kitrep "github.com/lessucettes/adresu-plugin/pkg/adresu-kit/reputation"
)

func (m *Manager) run(ctx context.Context, active *view, seeds []nostr.PubKey, source Source, done chan struct{}) {
	defer close(done)
	if snapshot, err := m.store.LoadReputationSnapshot(ctx); err != nil {
		slog.Warn("Could not restore reputation snapshot; collecting a new graph", "error", err)
	} else if usableSnapshot(snapshot, active, seeds) {
		active.snapshot.Store(snapshot)
		slog.Info("Restored local reputation snapshot", "nodes", snapshot.Nodes, "edges", snapshot.Edges)
	}
	retryDelay := min(5*time.Second, active.cfg.RefreshInterval)
	backoff := retryDelay
	for ctx.Err() == nil {
		err := m.refresh(ctx, active, seeds, source)
		delay := active.cfg.RefreshInterval
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.Warn("Local reputation refresh failed; retaining previous snapshot", "error", err)
			delay = backoff
			backoff = min(active.cfg.RefreshInterval, min(time.Minute, backoff*2))
		} else {
			backoff = retryDelay
			// Leave a full collection/persistence budget before the oldest
			// receipt expires, even when max_age equals refresh_interval.
			snapshot := active.snapshot.Load()
			refreshIn := time.Until(snapshot.ValidUntil) - refreshBudget(active.cfg)
			if refreshIn <= 0 {
				// Cached-only success may not advance ValidUntil. Retry soon,
				// but never turn a near-expiry snapshot into a tight loop.
				refreshIn = retryDelay
			}
			delay = min(delay, refreshIn)
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func refreshBudget(cfg config.ReputationConfig) time.Duration {
	return min(15*time.Minute, cfg.RefreshInterval, cfg.MaxAge/2)
}

func (m *Manager) refresh(ctx context.Context, active *view, seeds []nostr.PubKey, source Source) error {
	// A per-relay timeout does not bound a whole BFS with many batches.
	ctx, cancel := context.WithTimeout(ctx, refreshBudget(active.cfg))
	defer cancel()
	lists, coverage, validUntil, err := collect(ctx, active.cfg, seeds, source, m.store)
	if err != nil {
		return err
	}
	result, err := kitrep.Calculate(ctx, lists, seeds, kitrep.Options{
		Damping: active.cfg.Damping, Tolerance: active.cfg.Tolerance,
		MaxIterations: active.cfg.MaxIterations,
	})
	if err != nil {
		return fmt.Errorf("calculate local reputation: %w", err)
	}
	snapshot := &kitrep.Snapshot{
		ConfigID: active.id, CalculatedAt: time.Now().UTC(), ValidUntil: validUntil,
		Coverage: coverage, Nodes: result.Nodes, Edges: result.Edges, Scores: result.Scores,
	}
	if !usableSnapshot(snapshot, active, seeds) {
		return fmt.Errorf("calculated reputation snapshot is incomplete or expired")
	}
	if err := m.store.SaveReputationSnapshot(ctx, snapshot); err != nil {
		return fmt.Errorf("persist reputation snapshot: %w", err)
	}
	// The immutable result becomes visible only after its durable generation commits.
	active.snapshot.Store(snapshot)
	slog.Info("Local reputation snapshot updated", "nodes", result.Nodes, "edges", result.Edges, "coverage", coverage)
	return nil
}

func usableSnapshot(s *kitrep.Snapshot, active *view, seeds []nostr.PubKey) bool {
	if s == nil || s.ConfigID != active.id || s.Nodes != len(s.Scores) || s.Nodes < len(seeds) || s.Nodes > active.cfg.MaxNodes || s.Edges < 0 || s.Edges > active.cfg.MaxEdges {
		return false
	}
	now := time.Now()
	if s.CalculatedAt.IsZero() || s.CalculatedAt.After(now) || now.Sub(s.CalculatedAt) > active.cfg.MaxAge || !now.Before(s.ValidUntil) || s.ValidUntil.After(s.CalculatedAt.Add(active.cfg.MaxAge)) {
		return false
	}
	if math.IsNaN(s.Coverage) || s.Coverage < active.cfg.MinCoverage || s.Coverage > 1 {
		return false
	}
	for _, pk := range seeds {
		if _, ok := s.Scores[pk]; !ok {
			return false
		}
	}
	for _, score := range s.Scores {
		if math.IsNaN(score.TrustRank) || math.IsInf(score.TrustRank, 0) || score.TrustRank < 0 {
			return false
		}
	}
	return true
}
