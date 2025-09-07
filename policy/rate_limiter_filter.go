// policy/rate_limiter_filter.go
package policy

import (
	"adresu-plugin/config"
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/nbd-wtf/go-nostr"
	"golang.org/x/time/rate"
)

type RateLimiterFilter struct {
	cfg        *config.RateLimiterConfig
	limiters   *lru.LRU[string, *rate.Limiter]
	kindToRule map[int]*config.RateLimitRule
	mu         sync.Mutex
}

func NewRateLimiterFilter(cfg *config.RateLimiterConfig) *RateLimiterFilter {
	size := cfg.CacheSize
	if size <= 0 {
		size = 65536
	}
	ttl := cfg.TTL
	if ttl <= 0 {
		ttl = time.Minute * 10
	}

	cache := lru.NewLRU[string, *rate.Limiter](size, nil, ttl)

	kindMap := make(map[int]*config.RateLimitRule, len(cfg.Rules))
	for i := range cfg.Rules {
		rule := &cfg.Rules[i]
		for _, kind := range rule.Kinds {
			kindMap[kind] = rule
		}
	}

	return &RateLimiterFilter{
		cfg:        cfg,
		limiters:   cache,
		kindToRule: kindMap,
	}
}

func (f *RateLimiterFilter) Name() string { return "RateLimiterFilter" }

func (f *RateLimiterFilter) Check(ctx context.Context, event *nostr.Event, remoteIP string) *Result {
	if !f.cfg.Enabled {
		return Accept()
	}

	// Determine which rate and burst to use based on the event kind.
	var currentRate float64
	var currentBurst int
	var ruleDescription string

	if rule, exists := f.kindToRule[event.Kind]; exists {
		currentRate = rule.Rate
		currentBurst = rule.Burst
		ruleDescription = rule.Description
	} else {
		currentRate = f.cfg.DefaultRate
		currentBurst = f.cfg.DefaultBurst
		ruleDescription = "default"
	}

	// The rate must be positive for the rule to be active.
	if currentRate <= 0 {
		return Accept()
	}

	// Determine keys to limit by (IP, pubkey, or both).
	var userKeys []string
	switch f.cfg.By {
	case config.RateByIP:
		if remoteIP != "" {
			userKeys = append(userKeys, "ip:"+remoteIP)
		}
	case config.RateByPubKey:
		if event.PubKey != "" {
			userKeys = append(userKeys, "pk:"+event.PubKey)
		}
	case config.RateByBoth:
		if remoteIP != "" {
			userKeys = append(userKeys, "ip:"+remoteIP)
		}
		if event.PubKey != "" {
			userKeys = append(userKeys, "pk:"+event.PubKey)
		}
	}

	for _, userKey := range userKeys {
		// The cache key must be unique for each user AND each rule type.
		cacheKey := fmt.Sprintf("%s:%s", ruleDescription, userKey)
		limiter := f.getLimiter(cacheKey, currentRate, currentBurst)
		if !limiter.Allow() {
			return Reject(
				fmt.Sprintf("blocked: rate limit exceeded for %s", ruleDescription),
				slog.String("user_key", userKey),
				slog.String("rule_description", ruleDescription),
			)
		}
	}
	return Accept()
}

func (f *RateLimiterFilter) getLimiter(key string, r float64, b int) *rate.Limiter {
	if limiter, ok := f.limiters.Get(key); ok {
		return limiter
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if limiter, ok := f.limiters.Get(key); ok {
		return limiter
	}

	limiter := rate.NewLimiter(rate.Limit(r), b)
	f.limiters.Add(key, limiter)
	return limiter
}
