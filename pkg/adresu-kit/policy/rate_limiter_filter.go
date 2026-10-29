package policy

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"golang.org/x/time/rate"

	"github.com/lessucettes/adresu-plugin/pkg/adresu-kit/cache"
	"github.com/lessucettes/adresu-plugin/pkg/adresu-kit/config"
)

const (
	rateLimiterFilterName = "RateLimiterFilter"
)

type processedRateRule struct {
	rule *config.RateLimitRule
	id   string
}

type RateLimiterFilter struct {
	mu         sync.Mutex
	cfg        *config.RateLimiterConfig
	by         config.RateLimiterBy
	limiters   *cache.LRU[string, *rate.Limiter]
	kindToRule map[int]processedRateRule
}

func NewRateLimiterFilter(cfg *config.RateLimiterConfig) (*RateLimiterFilter, error) {
	size := cfg.CacheSize
	if size <= 0 {
		size = 65536
	}

	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = time.Minute * 10
	}

	// An omitted "by" must not disable limiting for an enabled filter.
	by := cfg.By
	if by == "" {
		by = config.RateByBoth
	}

	limiters := cache.NewLRU[string, *rate.Limiter](size, ttl)
	kindMap := make(map[int]processedRateRule, len(cfg.Rules))

	for i := range cfg.Rules {
		rule := &cfg.Rules[i]
		processed := processedRateRule{
			rule: rule,
			id:   "rule-" + strconv.Itoa(i),
		}
		for _, kind := range rule.Kinds {
			kindMap[kind] = processed
		}
	}

	filter := &RateLimiterFilter{
		cfg:        cfg,
		by:         by,
		limiters:   limiters,
		kindToRule: kindMap,
	}

	return filter, nil
}

func (f *RateLimiterFilter) Match(_ context.Context, event *nostr.Event, meta map[string]any) (FilterResult, error) {
	newResult := NewResultFunc(rateLimiterFilterName)

	if !f.cfg.Enabled {
		return newResult(true, "Filter is disabled.", nil)
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	var currentRate float64
	var currentBurst int
	var ruleID string
	var ruleDescription string

	if processed, exists := f.kindToRule[event.Kind]; exists {
		currentRate = processed.rule.Rate
		currentBurst = processed.rule.Burst
		ruleID = processed.id
		ruleDescription = processed.rule.Description
	} else {
		currentRate = f.cfg.DefaultRate
		currentBurst = f.cfg.DefaultBurst
		ruleID = "default"
		ruleDescription = "default"
	}

	if currentRate <= 0 {
		return newResult(true, "Publishing rate is unlimited for this event kind.", nil)
	}

	userKeys := make([]string, 0, 2)
	remoteIP, _ := meta["remote_ip"].(string)
	pubkey := authorKey(event)

	switch f.by {
	case config.RateByIP:
		if remoteIP != "" {
			userKeys = append(userKeys, "ip:"+remoteIP)
		}
	case config.RateByPubKey:
		if pubkey != "" {
			userKeys = append(userKeys, "pk:"+pubkey)
		}
	case config.RateByBoth:
		if remoteIP != "" {
			userKeys = append(userKeys, "ip:"+remoteIP)
		}
		if pubkey != "" {
			userKeys = append(userKeys, "pk:"+pubkey)
		}
	}

	for _, userKey := range userKeys {
		cacheKey := fmt.Sprintf("%s:%s", ruleID, userKey)
		limiter := f.getLimiter(cacheKey, currentRate, currentBurst)
		if !limiter.Allow() {
			reason := fmt.Sprintf("Publishing rate limit exceeded for rule %q.", ruleDescription)
			return newResult(false, reason, nil)
		}
	}
	return newResult(true, "Publishing rate is within the allowed limit.", nil)
}

func (f *RateLimiterFilter) getLimiter(key string, r float64, b int) *rate.Limiter {
	if limiter, ok := f.limiters.Get(key); ok {
		f.limiters.Add(key, limiter)
		return limiter
	}
	limiter := rate.NewLimiter(rate.Limit(r), b)
	f.limiters.Add(key, limiter)
	return limiter
}
