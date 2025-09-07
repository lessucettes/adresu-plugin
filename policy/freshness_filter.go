// policy/freshness_filter.go
package policy

import (
	"adresu-plugin/config"
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

type FreshnessFilter struct {
	mu  sync.RWMutex
	cfg *config.FreshnessFilterConfig
}

func NewFreshnessFilter(cfg *config.FreshnessFilterConfig) *FreshnessFilter {
	return &FreshnessFilter{
		cfg: cfg,
	}
}

func (f *FreshnessFilter) Name() string { return "FreshnessFilter" }

func (f *FreshnessFilter) Check(ctx context.Context, event *nostr.Event, remoteIP string) *Result {
	f.mu.RLock()
	cfg := f.cfg
	f.mu.RUnlock()

	now := time.Now()
	createdAt := event.CreatedAt.Time()

	age := now.Sub(createdAt)
	futureOffset := createdAt.Sub(now)

	if cfg.MaxPast > 0 && age > cfg.MaxPast {
		return Reject("blocked: event is too old",
			slog.String("age", age.Round(time.Second).String()),
			slog.String("created_at", createdAt.UTC().Format(time.RFC3339)),
		)
	}

	if cfg.MaxFuture > 0 && futureOffset > cfg.MaxFuture {
		return Reject("blocked: event timestamp is in the future",
			slog.String("future_offset", futureOffset.Round(time.Second).String()),
			slog.String("created_at", createdAt.UTC().Format(time.RFC3339)),
		)
	}

	return Accept()
}

func (f *FreshnessFilter) UpdateConfig(cfg *config.Config) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.cfg = &cfg.Filters.Freshness
	slog.Info("FreshnessFilter configuration updated",
		"max_past", f.cfg.MaxPast,
		"max_future", f.cfg.MaxFuture)
	return nil
}
