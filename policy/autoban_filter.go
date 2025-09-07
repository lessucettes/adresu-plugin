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
	mu sync.Mutex

	strikes         *lru.LRU[string, *RejectionStats]
	banningCooldown *lru.LRU[string, struct{}]

	store store.Store
	cfg   *config.AutoBanFilterConfig
}

// RejectionStats stores the violation history for a pubkey.
type RejectionStats struct {
	StrikeCount     int
	FirstStrikeTime time.Time
}

// NewAutoBanFilter wires dependencies and cache TTLs from config.
func NewAutoBanFilter(s store.Store, cfg *config.AutoBanFilterConfig) *AutoBanFilter {
	strikesCache := lru.NewLRU[string, *RejectionStats](cfg.StrikesCacheSize, nil, cfg.StrikeWindow)
	cooldownCache := lru.NewLRU[string, struct{}](cfg.CooldownCacheSize, nil, cfg.CooldownDuration)

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
	if !f.cfg.Enabled {
		return
	}
	if len(f.cfg.ExcludeFilters) > 0 && slices.Contains(f.cfg.ExcludeFilters, filterName) {
		return
	}

	pubkey := event.PubKey

	var (
		shouldBan        bool
		finalStrikeCount int
	)

	f.mu.Lock()

	if _, onCooldown := f.banningCooldown.Get(pubkey); onCooldown {
		f.mu.Unlock()
		return
	}

	stats, ok := f.strikes.Get(pubkey)
	if !ok {
		stats = &RejectionStats{StrikeCount: 1, FirstStrikeTime: time.Now()}
	} else {
		stats.StrikeCount++
	}
	f.strikes.Add(pubkey, stats)

	if stats.StrikeCount >= f.cfg.MaxStrikes {
		shouldBan = true
		finalStrikeCount = stats.StrikeCount
		f.strikes.Remove(pubkey)
		f.banningCooldown.Add(pubkey, struct{}{})
	}

	f.mu.Unlock()

	if shouldBan {
		slog.Warn("Auto-banning user for repeated violations",
			"pubkey", pubkey,
			"strike_count", finalStrikeCount,
			"ban_duration", f.cfg.BanDuration,
			"by_filter", filterName,
		)
		go f.banUser(pubkey)
	}
}

// banUser performs the ban operation in a separate goroutine.
func (f *AutoBanFilter) banUser(pubkey string) {
	timeout := f.cfg.BanTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	banCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if err := f.store.BanAuthor(banCtx, pubkey, f.cfg.BanDuration); err != nil {
		slog.Error("Failed to auto-ban author", "pubkey", pubkey, "error", err)
	}
}
