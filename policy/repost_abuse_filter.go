// policy/repost_abuse_filter.go
package policy

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"

	"adresu-plugin/config"

	lru "github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/nbd-wtf/go-nostr"
)

// UserActivityStats tracks per-pubkey posting behavior.
type UserActivityStats struct {
	OriginalPosts int
	Reposts       int
	LastEventTime time.Time
}

// RepostAbuseFilter observes user behavior and rejects users who mostly repost.
type RepostAbuseFilter struct {
	mu    sync.Mutex
	stats *lru.LRU[string, *UserActivityStats]
	cfg   *config.RepostAbuseFilterConfig
}

var nip21Re = regexp.MustCompile(`\b(naddr1|nevent1|note1)[0-9a-z]+\b`)

// NewRepostAbuseFilter constructs the filter from a configuration struct.
func NewRepostAbuseFilter(cfg *config.RepostAbuseFilterConfig) *RepostAbuseFilter {
	cache := lru.NewLRU[string, *UserActivityStats](50000, nil, cfg.CacheTTL)

	// Clamp max_ratio to a sane range [0.0, 1.0].
	if cfg.MaxRatio < 0 {
		cfg.MaxRatio = 0
	} else if cfg.MaxRatio > 1 {
		cfg.MaxRatio = 1
	}

	return &RepostAbuseFilter{
		stats: cache,
		cfg:   cfg,
	}
}

func (f *RepostAbuseFilter) Name() string { return "RepostAbuseFilter" }

// Check evaluates an incoming event.
func (f *RepostAbuseFilter) Check(ctx context.Context, event *nostr.Event, remoteIP string) *Result {
	// The first action is to check if the filter is enabled.
	if !f.cfg.Enabled {
		return Accept()
	}

	if event.Kind != nostr.KindTextNote && event.Kind != nostr.KindRepost && event.Kind != nostr.KindGenericRepost {
		return Accept()
	}

	// --- Step 1: Fetch stats under narrow lock and apply soft reset if needed.
	f.mu.Lock()
	stats, ok := f.stats.Get(event.PubKey)
	if !ok || stats == nil {
		stats = &UserActivityStats{}
	} else if f.cfg.ResetDuration > 0 && !stats.LastEventTime.IsZero() {
		if time.Since(stats.LastEventTime) > f.cfg.ResetDuration {
			// Soft reset for inactive users.
			stats.OriginalPosts = 0
			stats.Reposts = 0
		}
	}
	// Work on a copy outside the lock.
	statsCopy := *stats
	f.mu.Unlock()

	// --- Step 2: Classify the event per NIP-18.
	isRepost, cls := f.isRepostNIP18(event)

	// --- Step 3: Enforcement logic without holding the lock.
	shouldReject := false
	rejectionMsg := ""

	// Predictive ratio: if current event is a repost, evaluate as if counters included it.
	if isRepost {
		total := statsCopy.OriginalPosts + statsCopy.Reposts
		if total >= f.cfg.MinEvents {
			predictedReposts := statsCopy.Reposts + 1
			predictedTotal := total + 1

			var currentRatio float64
			if predictedTotal > 0 {
				currentRatio = float64(predictedReposts) / float64(predictedTotal)
			}

			if currentRatio >= f.cfg.MaxRatio {
				// Prepare log and user-facing message.
				ratioPercent := currentRatio * 100
				limitPercent := f.cfg.MaxRatio * 100
				slog.Warn("Rejecting event due to high repost ratio",
					"ip", remoteIP,
					"pubkey", event.PubKey,
					"event_id", event.ID,
					"classification", cls,
					"ratio_percent", fmt.Sprintf("%.1f%%", ratioPercent),
					"limit_percent", fmt.Sprintf("%.1f%%", limitPercent),
				)
				rejectionMsg = fmt.Sprintf(
					"blocked: too many reposts. Your repost ratio would be %.1f%%, the limit is %.1f%%. Please post original content.",
					ratioPercent, limitPercent,
				)
				shouldReject = true
			}
		}
	}

	// --- Step 4: Commit counters under narrow lock.
	f.mu.Lock()
	fresh, ok := f.stats.Get(event.PubKey)
	if !ok || fresh == nil {
		fresh = &UserActivityStats{}
	}
	// Optionally re-apply soft reset at commit time (covers time passed during Step 2/3).
	if f.cfg.ResetDuration > 0 && !fresh.LastEventTime.IsZero() {
		if time.Since(fresh.LastEventTime) > f.cfg.ResetDuration {
			fresh.OriginalPosts = 0
			fresh.Reposts = 0
		}
	}

	// Update LastEventTime depending on policy for rejected events.
	if !shouldReject || f.cfg.CountRejectAsActivity {
		fresh.LastEventTime = time.Now()
	}

	if !shouldReject {
		if isRepost {
			fresh.Reposts++
		} else {
			fresh.OriginalPosts++
		}
	}

	f.stats.Add(event.PubKey, fresh)
	f.mu.Unlock()

	if shouldReject {
		return Reject(rejectionMsg)
	}
	return Accept()
}

// isRepostNIP18 classifies events as reposts per NIP-18.
// Returns (true, classification) if it's a repost, where classification is one of
// "kind6", "kind16", "quote1". Otherwise returns (false, "").
func (f *RepostAbuseFilter) isRepostNIP18(ev *nostr.Event) (bool, string) {
	switch ev.Kind {
	case nostr.KindRepost: // 6
		// MUST include an 'e' tag with the id + relay URL; we count as repost regardless,
		// but log classification as kind6.
		return true, "kind6"
	case 16: // generic repost
		// SHOULD contain a "k" tag with kind number; we still count as repost.
		return true, "kind16"
	case nostr.KindTextNote: // 1
		// Quote reposts: kind 1 with a 'q' tag.
		if hasTag(ev, "q") {
			// Optionally require NIP-21 ref in content for stricter quote detection.
			if !f.cfg.RequireNIP21InQuote || contentHasNIP21Ref(ev.Content) {
				return true, "quote1"
			}
		}
	}
	return false, ""
}

func hasTag(ev *nostr.Event, tagName string) bool {
	for _, t := range ev.Tags {
		if len(t) > 0 && strings.EqualFold(t[0], tagName) {
			return true
		}
	}
	return false
}

func contentHasNIP21Ref(s string) bool {
	return nip21Re.MatchString(s)
}
