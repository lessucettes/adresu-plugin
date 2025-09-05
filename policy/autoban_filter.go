// policy/autoban_filter.go
package policy

import (
	"adresu-plugin/config"
	"adresu-plugin/store"
	"context"
	"log/slog"
	"slices"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/nbd-wtf/go-nostr"
)

// AutoBanFilter automatically bans users who repeatedly trigger rejections.
type AutoBanFilter struct {
	mu      sync.Mutex
	strikes *lru.LRU[string, *RejectionStats]
	store   store.Store
	cfg     *config.AutoBanFilterConfig // It now holds a reference to its config struct.

	// A short-term cache to prevent counting new strikes immediately after a ban.
	banningCooldown *lru.LRU[string, struct{}]
}

// RejectionStats stores the violation history for a pubkey.
type RejectionStats struct {
	StrikeCount     int
	FirstStrikeTime time.Time
}

// NewAutoBanFilter now accepts a config struct, following the standard pattern.
func NewAutoBanFilter(s store.Store, cfg *config.AutoBanFilterConfig) *AutoBanFilter {
	// Use strike_window from config for cache TTL.
	strikesCache := lru.NewLRU[string, *RejectionStats](cfg.StrikesCacheSize, nil, cfg.StrikeWindow)
	// Cooldown cache for 1 minute.
	cooldownCache := lru.NewLRU[string, struct{}](cfg.CooldownCacheSize, nil, time.Minute)

	return &AutoBanFilter{
		store:           s,
		strikes:         strikesCache,
		banningCooldown: cooldownCache,
		cfg:             cfg,
	}
}

func (f *AutoBanFilter) Name() string { return "AutoBanFilter" }

// Check does nothing, as this filter only acts on rejections.
func (f *AutoBanFilter) Check(ctx context.Context, event *nostr.Event, remoteIP string) *Result {
	return Accept()
}

// HandleRejection is called when an event has been rejected by another filter.
func (f *AutoBanFilter) HandleRejection(ctx context.Context, event *nostr.Event, filterName string) {
	// The first action is to check if the filter is enabled.
	if !f.cfg.Enabled {
		return
	}

	if len(f.cfg.ExcludeFilters) > 0 {
		if slices.Contains(f.cfg.ExcludeFilters, filterName) {
			return
		}
	}

	pubkey := event.PubKey

	if _, onCooldown := f.banningCooldown.Get(pubkey); onCooldown {
		return
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	if _, onCooldown := f.banningCooldown.Get(pubkey); onCooldown {
		return
	}

	stats, ok := f.strikes.Get(pubkey)
	if !ok {
		stats = &RejectionStats{StrikeCount: 1, FirstStrikeTime: time.Now()}
	} else {
		stats.StrikeCount++
	}

	f.strikes.Add(pubkey, stats)

	// Use MaxStrikes from the config.
	if stats.StrikeCount >= f.cfg.MaxStrikes {
		slog.Warn("Auto-banning user for repeated violations",
			"pubkey", pubkey,
			"strike_count", stats.StrikeCount,
			"ban_duration", f.cfg.BanDuration)

		go f.banUser(ctx, pubkey)

		f.strikes.Remove(pubkey)
		f.banningCooldown.Add(pubkey, struct{}{})
	}
}

// banUser performs the ban operation in a separate goroutine.
func (f *AutoBanFilter) banUser(ctx context.Context, pubkey string) {
	banCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Use BanDuration from the config.
	if err := f.store.BanAuthor(banCtx, pubkey, f.cfg.BanDuration); err != nil {
		slog.Error("Failed to auto-ban author", "pubkey", pubkey, "error", err)
	}
}
