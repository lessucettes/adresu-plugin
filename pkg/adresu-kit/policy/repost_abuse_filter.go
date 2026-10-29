package policy

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/nbd-wtf/go-nostr"

	"github.com/lessucettes/adresu-plugin/pkg/adresu-kit/cache"
	"github.com/lessucettes/adresu-plugin/pkg/adresu-kit/config"
)

const (
	repostAbuseFilterName = "RepostAbuseFilter"
)

type UserActivityStats struct {
	OriginalPosts int
	Reposts       int
	LastEventTime time.Time
}

type RepostAbuseFilter struct {
	mu    sync.Mutex
	stats *cache.LRU[string, *UserActivityStats]
	cfg   *config.RepostAbuseFilterConfig
}

var nip21Re = regexp.MustCompile(`\b(naddr1|nevent1|note1)[0-9a-z]+\b`)

func NewRepostAbuseFilter(cfg *config.RepostAbuseFilterConfig) (*RepostAbuseFilter, error) {
	size := cfg.CacheSize
	statsCache := cache.NewLRU[string, *UserActivityStats](size, cfg.CacheTTL)

	if cfg.MaxRatio < 0 {
		cfg.MaxRatio = 0
	} else if cfg.MaxRatio > 1 {
		cfg.MaxRatio = 1
	}

	filter := &RepostAbuseFilter{
		stats: statsCache,
		cfg:   cfg,
	}

	return filter, nil
}

func (f *RepostAbuseFilter) Match(_ context.Context, event *nostr.Event, meta map[string]any) (FilterResult, error) {
	newResult := NewResultFunc(repostAbuseFilterName)

	if !f.cfg.Enabled {
		return newResult(true, "Filter is disabled.", nil)
	}
	if event.Kind != nostr.KindTextNote && event.Kind != nostr.KindRepost && event.Kind != nostr.KindGenericRepost {
		return newResult(true, "Repost ratio check does not apply to this event kind.", nil)
	}

	isRepost, _ := f.isRepostNIP18(event)
	pubkey := authorKey(event)

	f.mu.Lock()
	defer f.mu.Unlock()

	stats, ok := f.stats.Get(pubkey)
	if !ok || stats == nil {
		stats = &UserActivityStats{}
	} else if f.cfg.ResetDuration > 0 && !stats.LastEventTime.IsZero() {
		if time.Since(stats.LastEventTime) > f.cfg.ResetDuration {
			stats.OriginalPosts, stats.Reposts = 0, 0
		}
	}

	var rejectionReason string
	if isRepost {
		total := stats.OriginalPosts + stats.Reposts
		if total >= f.cfg.MinEvents {
			predictedReposts := stats.Reposts + 1
			predictedTotal := total + 1
			currentRatio := float64(predictedReposts) / float64(predictedTotal)
			if currentRatio >= f.cfg.MaxRatio {
				ratioPercent := currentRatio * 100
				limitPercent := f.cfg.MaxRatio * 100
				rejectionReason = fmt.Sprintf(
					"Publishing this repost would make the repost share %.1f%%, reaching or exceeding the %.1f%% limit.",
					ratioPercent, limitPercent,
				)
			}
		}
	}

	if rejectionReason == "" || f.cfg.CountRejectAsActivity {
		stats.LastEventTime = time.Now()
	}
	if rejectionReason == "" {
		if isRepost {
			stats.Reposts++
		} else {
			stats.OriginalPosts++
		}
	}
	f.stats.Add(pubkey, stats)

	if rejectionReason != "" {
		return newResult(false, rejectionReason, nil)
	}
	return newResult(true, "Event passes the repost ratio check.", nil)
}

func (f *RepostAbuseFilter) isRepostNIP18(ev *nostr.Event) (bool, string) {
	switch ev.Kind {
	case nostr.KindRepost:
		return true, "kind6"
	case 16:
		return true, "kind16"
	case nostr.KindTextNote:
		if hasTag(ev, "q") {
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
