package policy

import (
	"context"
	"fmt"
	"time"

	"github.com/nbd-wtf/go-nostr"

	"github.com/lessucettes/adresu-plugin/pkg/adresu-kit/config"
)

const (
	freshnessFilterName = "FreshnessFilter"
)

type timeLimits struct {
	MaxPast   time.Duration
	MaxFuture time.Duration
}

type FreshnessFilter struct {
	cfg         *config.FreshnessFilterConfig
	rulesByKind map[int]timeLimits
}

func NewFreshnessFilter(cfg *config.FreshnessFilterConfig) (*FreshnessFilter, error) {
	rulesByKind := make(map[int]timeLimits)

	if cfg != nil {
		for _, rule := range cfg.Rules {
			limits := timeLimits{
				MaxPast:   rule.MaxPast,
				MaxFuture: rule.MaxFuture,
			}
			for _, kind := range rule.Kinds {
				rulesByKind[kind] = limits
			}
		}
	}

	filter := &FreshnessFilter{
		cfg:         cfg,
		rulesByKind: rulesByKind,
	}

	return filter, nil
}

func (f *FreshnessFilter) Match(_ context.Context, event *nostr.Event, meta map[string]any) (FilterResult, error) {
	newResult := NewResultFunc(freshnessFilterName)

	maxPast, maxFuture := f.cfg.DefaultMaxPast, f.cfg.DefaultMaxFuture

	if limits, ok := f.rulesByKind[event.Kind]; ok {
		maxPast = limits.MaxPast
		maxFuture = limits.MaxFuture
	}

	now := time.Now()
	createdAt := event.CreatedAt.Time()

	age := now.Sub(createdAt)
	if maxPast > 0 && age > maxPast {
		reason := fmt.Sprintf("event_too_old:age_%s,max_%s", age.Round(time.Second), maxPast)
		return newResult(false, reason, nil)
	}

	futureOffset := createdAt.Sub(now)
	if maxFuture > 0 && futureOffset > maxFuture {
		reason := fmt.Sprintf("event_in_future:offset_%s,max_%s", futureOffset.Round(time.Second), maxFuture)
		return newResult(false, reason, nil)
	}

	return newResult(true, "timestamp_ok", nil)
}
