package policy

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"sync"
	"time"

	"fiatjaf.com/nostr"

	lru "github.com/lessucettes/adresu-plugin/pkg/adresu-kit/cache"
	"github.com/lessucettes/adresu-plugin/pkg/adresu-kit/nip"

	"github.com/lessucettes/adresu-plugin/internal/config"
	"github.com/lessucettes/adresu-plugin/internal/store"
)

// AutoBanFilter automatically bans users who repeatedly trigger rejections.
type AutoBanFilter struct {
	mu sync.Mutex

	strikes         *lru.LRU[nostr.PubKey, *RejectionStats]
	banningCooldown *lru.LRU[nostr.PubKey, struct{}]

	store store.Store
	cfg   *config.AutoBanFilterConfig

	closed bool
	wg     sync.WaitGroup
}

// RejectionStats stores the violation history for a pubkey.
type RejectionStats struct {
	StrikeCount     int
	FirstStrikeTime time.Time
	EventIDs        []nostr.ID
}

// NewAutoBanFilter wires dependencies and cache TTLs from config.
func NewAutoBanFilter(s store.Store, cfg *config.AutoBanFilterConfig) (*AutoBanFilter, error) {
	if cfg == nil {
		return nil, errors.New("autoban config is nil")
	}

	filter := &AutoBanFilter{store: s, cfg: cfg}
	if !cfg.Enabled {
		// Disabled autoban never records strikes; do not allocate its caches.
		return filter, nil
	}

	filter.strikes = lru.NewLRU[nostr.PubKey, *RejectionStats](cfg.StrikesCacheSize, cfg.StrikeWindow)
	filter.banningCooldown = lru.NewLRU[nostr.PubKey, struct{}](cfg.CooldownCacheSize, cfg.CooldownDuration)
	return filter, nil
}

// HandleRejection is called when an event has been rejected by another filter.
func (f *AutoBanFilter) HandleRejection(ctx context.Context, event *nostr.Event, filterName string) {
	if !f.cfg.Enabled {
		return
	}
	if f.cfg.MaxStrikes <= 0 {
		// Invalid configuration must not turn every rejection into a ban.
		slog.Error("Autoban is enabled with a non-positive max_strikes; skipping")
		return
	}
	if len(f.cfg.ExcludeFilters) > 0 && slices.Contains(f.cfg.ExcludeFilters, filterName) {
		return
	}
	if event == nil {
		return
	}
	// The signature covers the event body, not its ID field. An event whose ID
	// disagrees with the body it carries is not the object its author signed,
	// so it must not contribute strikes or poison replay accounting.
	eventID := nip.CanonicalEventID(ctx, event)
	if event.ID != eventID {
		return
	}
	// Never punish an identity supplied by an event its author did not sign.
	// This also prevents a forged moderator reaction from banning the moderator.
	valid, err := nip.CheckEventSignature(ctx, event)
	if err != nil || !valid {
		return
	}

	pubkey := event.PubKey

	var (
		shouldBan        bool
		finalStrikeCount int
	)

	f.mu.Lock()

	if f.closed {
		f.mu.Unlock()
		return
	}
	if _, onCooldown := f.banningCooldown.Get(pubkey); onCooldown {
		f.mu.Unlock()
		return
	}

	now := time.Now()
	stats, ok := f.strikes.Get(pubkey)
	if !ok || now.Sub(stats.FirstStrikeTime) >= f.cfg.StrikeWindow {
		stats = &RejectionStats{FirstStrikeTime: now}
	}
	// Anyone can relay a signed Nostr event. Replaying one rejected event
	// must not create additional strikes against its original author.
	if slices.Contains(stats.EventIDs, eventID) {
		f.mu.Unlock()
		return
	}
	stats.EventIDs = append(stats.EventIDs, eventID)
	stats.StrikeCount++
	f.strikes.Add(pubkey, stats)

	if stats.StrikeCount >= f.cfg.MaxStrikes {
		shouldBan = true
		finalStrikeCount = stats.StrikeCount
		f.strikes.Remove(pubkey)
		f.banningCooldown.Add(pubkey, struct{}{})
		f.wg.Add(1)
	}

	f.mu.Unlock()

	if shouldBan {
		slog.Warn("Auto-banning user for repeated violations",
			"pubkey", pubkey.Hex(),
			"strike_count", finalStrikeCount,
			"ban_duration", f.cfg.BanDuration,
			"by_filter", filterName,
		)
		go func() {
			defer f.wg.Done()
			f.banUser(ctx, pubkey)
		}()
	}
}

// Close waits for in-flight ban operations. It must not be called concurrently
// with HandleRejection.
func (f *AutoBanFilter) Close() error {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
	f.wg.Wait()
	return nil
}

// banUser performs the ban operation in a separate goroutine.
func (f *AutoBanFilter) banUser(parentCtx context.Context, pubkey nostr.PubKey) {
	timeout := f.cfg.BanTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	// Finish an admitted ban even if its triggering request is canceled;
	// the timeout bounds its lifetime and Close joins it before storage closes.
	banCtx, cancel := context.WithTimeout(context.WithoutCancel(parentCtx), timeout)
	defer cancel()

	if err := f.store.BanAuthor(banCtx, pubkey.Hex(), f.cfg.BanDuration); err != nil {
		select {
		case <-banCtx.Done():
			slog.Warn("Auto-ban cancelled by context", "pubkey", pubkey.Hex(), "error", banCtx.Err())
		default:
			slog.Error("Failed to auto-ban author", "pubkey", pubkey.Hex(), "error", err)
		}
	}
}
