// policy/freshness_filter.go
package policy

import (
	"adresu-plugin/config"
	"context"
	"log/slog"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/nbd-wtf/go-nostr"
)

type FreshnessFilter struct {
	mu        sync.RWMutex
	cfg       *config.FreshnessFilterConfig
	warnCache *lru.LRU[string, time.Time]
}

func NewFreshnessFilter(cfg *config.FreshnessFilterConfig) *FreshnessFilter {
	cache := lru.NewLRU[string, time.Time](4096, nil, 10*time.Minute)
	return &FreshnessFilter{
		cfg:       cfg,
		warnCache: cache,
	}
}

func (f *FreshnessFilter) Name() string { return "FreshnessFilter" }

func (f *FreshnessFilter) Check(ctx context.Context, event *nostr.Event, remoteIP string) *Result {
	f.mu.RLock()
	cfg := f.cfg
	f.mu.RUnlock()

	now := time.Now()
	createdAt := event.CreatedAt.Time()

	tooOld := cfg.MaxPast > 0 && now.Sub(createdAt) > cfg.MaxPast
	tooFuture := cfg.MaxFuture > 0 && createdAt.Sub(now) > cfg.MaxFuture

	if !tooOld && !tooFuture {
		return Accept()
	}

	shouldLog := false
	key := event.PubKey

	f.mu.Lock()
	if lastWarn, ok := f.warnCache.Get(key); !ok || now.Sub(lastWarn) > time.Minute {
		f.warnCache.Add(key, now)
		shouldLog = true
	}
	f.mu.Unlock()

	if shouldLog {
		if tooOld {
			slog.Warn("Rejecting stale event",
				"ip", remoteIP, "pubkey", event.PubKey, "event_id", event.ID,
				"created_at", createdAt, "age", now.Sub(createdAt))
		} else {
			slog.Warn("Rejecting future-dated event",
				"ip", remoteIP, "pubkey", event.PubKey, "event_id", event.ID,
				"created_at", createdAt, "future_offset", createdAt.Sub(now))
		}
	}

	if tooOld {
		return Reject("blocked: event is too old")
	}
	return Reject("blocked: event timestamp is in the future")
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
