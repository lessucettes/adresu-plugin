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

type timeLimits struct {
	MaxPast   time.Duration
	MaxFuture time.Duration
}

type FreshnessFilter struct {
	mu          sync.RWMutex
	cfg         *config.FreshnessFilterConfig
	rulesByKind map[int]timeLimits
}

func NewFreshnessFilter(cfg *config.FreshnessFilterConfig) *FreshnessFilter {
	f := &FreshnessFilter{
		cfg: cfg,
	}
	f.buildRuleMap()
	return f
}

func (f *FreshnessFilter) buildRuleMap() {
	f.rulesByKind = make(map[int]timeLimits)
	if f.cfg == nil {
		return
	}
	for _, rule := range f.cfg.Rules {
		limits := timeLimits{
			MaxPast:   rule.MaxPast,
			MaxFuture: rule.MaxFuture,
		}
		for _, kind := range rule.Kinds {
			f.rulesByKind[kind] = limits
		}
	}
}

func (f *FreshnessFilter) Name() string { return "FreshnessFilter" }

func (f *FreshnessFilter) Check(ctx context.Context, event *nostr.Event, remoteIP string) *Result {
	f.mu.RLock()
	rulesMap := f.rulesByKind
	defaultMaxPast := f.cfg.DefaultMaxPast
	defaultMaxFuture := f.cfg.DefaultMaxFuture
	f.mu.RUnlock()

	maxPast, maxFuture := defaultMaxPast, defaultMaxFuture

	if limits, ok := rulesMap[event.Kind]; ok {
		maxPast = limits.MaxPast
		maxFuture = limits.MaxFuture
	}

	now := time.Now()
	createdAt := event.CreatedAt.Time()

	age := now.Sub(createdAt)
	futureOffset := createdAt.Sub(now)

	if maxPast > 0 && age > maxPast {
		return Reject("blocked: event is too old",
			slog.String("age", age.Round(time.Second).String()),
			slog.String("created_at", createdAt.UTC().Format(time.RFC3339)),
		)
	}

	if maxFuture > 0 && futureOffset > maxFuture {
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
	f.buildRuleMap()

	slog.Info("FreshnessFilter configuration updated",
		"default_max_past", f.cfg.DefaultMaxPast,
		"default_max_future", f.cfg.DefaultMaxFuture,
		"rules_count", len(f.cfg.Rules))
	return nil
}
