// policy/ephemeral_chat_filter.go
package policy

import (
	"adresu-plugin/config"
	"context"
	"fmt"
	"log/slog"
	"math/bits"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	lru "github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/nbd-wtf/go-nostr"
	"golang.org/x/time/rate"
)

// activeChatConfig holds a snapshot of the configuration and its derived data.
type activeChatConfig struct {
	raw        *config.EphemeralChatFilterConfig
	zalgoRegex *regexp.Regexp
	wordRegex  *regexp.Regexp
}

type EphemeralChatFilter struct {
	mu        sync.RWMutex
	activeCfg *activeChatConfig

	// Caches are stateful and kept separate from the reloadable config.
	lastSeen *lru.LRU[string, time.Time]
	limiters *lru.LRU[string, *rate.Limiter]
}

var hexToLeadingZeros [256]int

func init() {
	// Pre-compute leading zero bits for each possible hex character value.
	for i := 0; i < 256; i++ {
		char := byte(i)
		var val uint64
		if char >= '0' && char <= '9' {
			val, _ = strconv.ParseUint(string(char), 16, 4)
		} else if char >= 'a' && char <= 'f' {
			val, _ = strconv.ParseUint(string(char), 16, 4)
		} else if char >= 'A' && char <= 'F' {
			val, _ = strconv.ParseUint(string(char), 16, 4)
		} else {
			hexToLeadingZeros[i] = -1 // Mark as invalid
			continue
		}
		hexToLeadingZeros[i] = bits.LeadingZeros8(uint8(val << 4))
	}
}

// NewEphemeralChatFilter creates a new filter for ephemeral chats.
func NewEphemeralChatFilter(cfg *config.EphemeralChatFilterConfig) *EphemeralChatFilter {
	f := &EphemeralChatFilter{}
	f.activeCfg = f.buildActiveConfig(cfg)
	f.initCaches(cfg)
	return f
}

func (f *EphemeralChatFilter) Name() string { return "EphemeralChatFilter" }

func (f *EphemeralChatFilter) Check(ctx context.Context, event *nostr.Event, remoteIP string) *Result {
	f.mu.RLock()
	cfg := f.activeCfg
	f.mu.RUnlock()

	if !cfg.raw.Enabled || !slices.Contains(cfg.raw.Kinds, event.Kind) {
		return Accept()
	}

	if f.lastSeen != nil && cfg.raw.MinDelay > 0 {
		now := time.Now()
		if last, ok := f.lastSeen.Get(event.PubKey); ok {
			delay := now.Sub(last)
			if delay < cfg.raw.MinDelay {
				return Reject("blocked: posting too frequently in chat",
					slog.String("delay", delay.String()),
					slog.String("limit", cfg.raw.MinDelay.String()),
				)
			}
		}
		f.lastSeen.Add(event.PubKey, now)
	}

	content := event.Content

	if cfg.raw.MaxCapsRatio > 0 {
		letters, caps := 0, 0
		for _, r := range content {
			if unicode.IsLetter(r) {
				letters++
				if unicode.IsUpper(r) {
					caps++
				}
			}
		}
		minLetters := cfg.raw.MinLettersForCapsCheck
		if minLetters <= 0 {
			minLetters = 20
		}
		if letters > minLetters {
			ratio := float64(caps) / float64(letters)
			if ratio > cfg.raw.MaxCapsRatio {
				return Reject("blocked: excessive use of capital letters",
					slog.Float64("caps_ratio", ratio),
					slog.Float64("limit", cfg.raw.MaxCapsRatio),
				)
			}
		}
	}

	if cfg.raw.MaxRepeatChars > 0 {
		runes := []rune(content)
		if len(runes) >= cfg.raw.MaxRepeatChars {
			count := 1
			for i := 1; i < len(runes); i++ {
				if runes[i] == runes[i-1] {
					count++
				} else {
					count = 1
				}
				if count >= cfg.raw.MaxRepeatChars {
					return Reject("blocked: excessive character repetition",
						slog.Int("repetitions", count),
						slog.Int("limit", cfg.raw.MaxRepeatChars),
					)
				}
			}
		}
	}
	if cfg.wordRegex != nil && cfg.wordRegex.MatchString(content) {
		return Reject("blocked: message contains words that are too long",
			slog.Int("limit", cfg.raw.MaxWordLength),
		)
	}
	if cfg.zalgoRegex != nil && cfg.zalgoRegex.MatchString(content) {
		return Reject("blocked: message contains Zalgo text")
	}

	limiter := f.getLimiter(event.PubKey, cfg)
	if limiter.Allow() {
		return Accept()
	}

	if IsPoWValid(event, cfg.raw.RequiredPoWOnLimit) {
		return Accept()
	}

	return Reject(
		fmt.Sprintf("blocked: chat rate limit exceeded. Attach PoW of difficulty %d to send.", cfg.raw.RequiredPoWOnLimit),
		slog.Int("required_pow", cfg.raw.RequiredPoWOnLimit),
		slog.Bool("pow_fallback_failed", true),
	)
}

// UpdateConfig atomically replaces the filter's configuration.
func (f *EphemeralChatFilter) UpdateConfig(newGlobalCfg *config.Config) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	newCfg := &newGlobalCfg.Filters.EphemeralChat

	f.initCaches(newCfg)

	if f.activeCfg.raw.CacheSize != newCfg.CacheSize {
		slog.Info("EphemeralChatFilter cache_size updated", "old", f.activeCfg.raw.CacheSize, "new", newCfg.CacheSize)
	}

	newActiveCfg := f.buildActiveConfig(newCfg)
	f.activeCfg = newActiveCfg

	slog.Info("EphemeralChatFilter config updated successfully.")
	return nil
}

// buildActiveConfig creates a new configuration snapshot with compiled regexes.
func (f *EphemeralChatFilter) buildActiveConfig(cfg *config.EphemeralChatFilterConfig) *activeChatConfig {
	ac := &activeChatConfig{raw: cfg}
	if cfg.BlockZalgo {
		ac.zalgoRegex = regexp.MustCompile(`\p{M}`)
	}
	if cfg.MaxWordLength > 0 {
		ac.wordRegex = regexp.MustCompile(fmt.Sprintf(`\S{%d,}`, cfg.MaxWordLength))
	}
	return ac
}

// initCaches initializes the stateful LRU caches.
func (f *EphemeralChatFilter) initCaches(cfg *config.EphemeralChatFilterConfig) {
	if !cfg.Enabled {
		f.lastSeen = nil
		f.limiters = nil
		return
	}

	size := cfg.CacheSize
	if size <= 0 {
		size = 10000
	}
	f.lastSeen = lru.NewLRU[string, time.Time](size, nil, 5*time.Minute)
	f.limiters = lru.NewLRU[string, *rate.Limiter](size, nil, 15*time.Minute)
}

func (f *EphemeralChatFilter) getLimiter(key string, cfg *activeChatConfig) *rate.Limiter {
	if f.limiters == nil {
		slog.Warn("EphemeralChatFilter is enabled, but caches are not initialized (likely due to hot-reload). Rate limiting is currently inactive. A restart may be required.")
		return rate.NewLimiter(rate.Inf, 0)
	}
	if limiter, ok := f.limiters.Get(key); ok {
		return limiter
	}
	limiter := rate.NewLimiter(rate.Limit(cfg.raw.RateLimitRate), cfg.raw.RateLimitBurst)
	f.limiters.Add(key, limiter)
	return limiter
}

// countLeadingZeroBits calculates the number of leading zero bits in a hex string using a lookup table.
func countLeadingZeroBits(hexString string) int {
	count := 0
	for i := 0; i < len(hexString); i++ {
		char := hexString[i]
		zeros := hexToLeadingZeros[char]

		if zeros == -1 { // Invalid hex character
			return count
		}

		count += zeros
		if zeros != 4 { // Stop if it's not a '0' character
			break
		}
	}
	return count
}

// IsPoWValid checks if an event has a valid Proof of Work of at least minDifficulty.
func IsPoWValid(event *nostr.Event, minDifficulty int) bool {
	actualDifficulty := countLeadingZeroBits(event.ID)
	if actualDifficulty < minDifficulty {
		return false
	}

	nonceTag := event.Tags.FindLast("nonce")
	if len(nonceTag) < 3 {
		return false
	}

	// Correctly parse the full string from the tag.
	claimedDifficulty, err := strconv.Atoi(strings.TrimSpace(nonceTag[2]))
	if err != nil {
		return false
	}
	return claimedDifficulty >= minDifficulty
}
