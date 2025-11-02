package policy

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/nbd-wtf/go-nostr"

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
	stats *lru.LRU[string, *UserActivityStats]
	cfg   *config.RepostAbuseFilterConfig
}

var nip21Re = regexp.MustCompile(`\b(naddr1|nevent1|note1)[0-9a-z]+\b`)

func NewRepostAbuseFilter(cfg *config.RepostAbuseFilterConfig) (*RepostAbuseFilter, error) {
	size := cfg.CacheSize
	cache := lru.NewLRU[string, *UserActivityStats](size, nil, cfg.CacheTTL)

	if cfg.MaxRatio < 0 {
		cfg.MaxRatio = 0
	} else if cfg.MaxRatio > 1 {
		cfg.MaxRatio = 1
	}

	filter := &RepostAbuseFilter{
		stats: cache,
		cfg:   cfg,
	}

	return filter, nil
}

func (f *RepostAbuseFilter) Match(_ context.Context, event *nostr.Event, meta map[string]any) (FilterResult, error) {
	newResult := NewResultFunc(repostAbuseFilterName)

	if !f.cfg.Enabled {
		return newResult(true, "filter_disabled", nil)
	}
	if event.Kind != nostr.KindTextNote && event.Kind != nostr.KindRepost && event.Kind != nostr.KindGenericRepost {
		return newResult(true, "kind_not_checked", nil)
	}

	f.mu.Lock()
	stats, ok := f.stats.Get(event.PubKey)
	if !ok || stats == nil {
		stats = &UserActivityStats{}
	} else if f.cfg.ResetDuration > 0 && !stats.LastEventTime.IsZero() {
		if time.Since(stats.LastEventTime) > f.cfg.ResetDuration {
			stats.OriginalPosts, stats.Reposts = 0, 0
		}
	}
	statsCopy := *stats
	f.mu.Unlock()

	isRepost, _ := f.isRepostNIP18(event)
	var rejectionReason string

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
				ratioPercent := currentRatio * 100
				limitPercent := f.cfg.MaxRatio * 100
				rejectionReason = fmt.Sprintf(
					"repost_ratio_too_high:would_be_%.1f%%,limit_is_%.1f%%",
					ratioPercent, limitPercent,
				)
			}
		}
	}

	f.mu.Lock()
	fresh, ok := f.stats.Get(event.PubKey)
	if !ok || fresh == nil {
		fresh = &UserActivityStats{}
	}
	if f.cfg.ResetDuration > 0 && !fresh.LastEventTime.IsZero() {
		if time.Since(fresh.LastEventTime) > f.cfg.ResetDuration {
			fresh.OriginalPosts, fresh.Reposts = 0, 0
		}
	}
	if rejectionReason == "" || f.cfg.CountRejectAsActivity {
		fresh.LastEventTime = time.Now()
	}
	if rejectionReason == "" {
		if isRepost {
			fresh.Reposts++
		} else {
			fresh.OriginalPosts++
		}
	}
	f.stats.Add(event.PubKey, fresh)
	f.mu.Unlock()

	if rejectionReason != "" {
		return newResult(false, rejectionReason, nil)
	}
	return newResult(true, "repost_ratio_ok", nil)
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
