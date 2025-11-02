package policy

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"time"
	"unicode"

	lru "github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/nbd-wtf/go-nostr"
	"golang.org/x/time/rate"

	"github.com/lessucettes/adresu-plugin/pkg/adresu-kit/config"
	"github.com/lessucettes/adresu-plugin/pkg/adresu-kit/nip"
)

const (
	ephemeralChatFilterName = "EphemeralChatFilter"
)

type EphemeralChatFilter struct {
	cfg        *config.EphemeralChatFilterConfig
	zalgoRegex *regexp.Regexp
	wordRegex  *regexp.Regexp
	lastSeen   *lru.LRU[string, time.Time]
	limiters   *lru.LRU[string, *rate.Limiter]
}

func NewEphemeralChatFilter(cfg *config.EphemeralChatFilterConfig) (*EphemeralChatFilter, error) {
	if !cfg.Enabled {
		return &EphemeralChatFilter{cfg: cfg}, nil
	}

	var zalgoRegex, wordRegex *regexp.Regexp
	var err error

	if cfg.BlockZalgo {
		zalgoRegex = regexp.MustCompile("[\u0300-\u036F\u1AB0-\u1AFF\u1DC0-\u1DFF\u20D0-\u20FF\uFE20-\uFE2F]")
	}
	if cfg.MaxWordLength > 0 {
		wordRegex, err = regexp.Compile(fmt.Sprintf(`\S{%d,}`, cfg.MaxWordLength))
		if err != nil {
			return nil, fmt.Errorf("invalid max_word_length generates bad regexp: %w", err)
		}
	}

	size := cfg.CacheSize
	if size <= 0 {
		size = 10000
	}
	lastSeen := lru.NewLRU[string, time.Time](size, nil, 5*time.Minute)
	limiters := lru.NewLRU[string, *rate.Limiter](size, nil, 15*time.Minute)

	filter := &EphemeralChatFilter{
		cfg:        cfg,
		zalgoRegex: zalgoRegex,
		wordRegex:  wordRegex,
		lastSeen:   lastSeen,
		limiters:   limiters,
	}

	return filter, nil
}

func (f *EphemeralChatFilter) Match(_ context.Context, event *nostr.Event, meta map[string]any) (FilterResult, error) {
	newResult := NewResultFunc(ephemeralChatFilterName)

	if !f.cfg.Enabled || !slices.Contains(f.cfg.Kinds, event.Kind) {
		return newResult(true, "filter_disabled_or_kind_not_matched", nil)
	}

	if f.lastSeen != nil && f.cfg.MinDelay > 0 {
		now := time.Now()
		if last, ok := f.lastSeen.Get(event.PubKey); ok {
			if delay := now.Sub(last); delay < f.cfg.MinDelay {
				reason := fmt.Sprintf("posting_too_frequently:delay_%.1fs,limit_%.1fs", delay.Seconds(), f.cfg.MinDelay.Seconds())
				return newResult(false, reason, nil)
			}
		}
		f.lastSeen.Add(event.PubKey, now)
	}

	content := event.Content

	if f.cfg.MaxCapsRatio > 0 {
		letters, caps := 0, 0
		for _, r := range content {
			if unicode.IsLetter(r) {
				letters++
				if unicode.IsUpper(r) {
					caps++
				}
			}
		}
		minLetters := f.cfg.MinLettersForCapsCheck
		if minLetters <= 0 {
			minLetters = 20
		}
		if letters > minLetters {
			if ratio := float64(caps) / float64(letters); ratio > f.cfg.MaxCapsRatio {
				reason := fmt.Sprintf("excessive_caps:ratio_%.2f,limit_%.2f", ratio, f.cfg.MaxCapsRatio)
				return newResult(false, reason, nil)
			}
		}
	}

	if f.cfg.MaxRepeatChars > 0 {
		runes := []rune(content)
		if len(runes) >= f.cfg.MaxRepeatChars {
			count := 1
			for i := 1; i < len(runes); i++ {
				if runes[i] == runes[i-1] {
					count++
				} else {
					count = 1
				}
				if count >= f.cfg.MaxRepeatChars {
					reason := fmt.Sprintf("excessive_char_repetition:count_%d,limit_%d", count, f.cfg.MaxRepeatChars)
					return newResult(false, reason, nil)
				}
			}
		}
	}

	if f.wordRegex != nil && f.wordRegex.MatchString(content) {
		return newResult(false, fmt.Sprintf("word_too_long:limit_%d", f.cfg.MaxWordLength), nil)
	}

	if f.zalgoRegex != nil && f.zalgoRegex.MatchString(content) {
		return newResult(false, "zalgo_text_detected", nil)
	}

	limiter := f.getLimiter(event.PubKey)
	if limiter.Allow() {
		return newResult(true, "rate_limit_ok", nil)
	}

	if nip.IsPoWValid(event, f.cfg.RequiredPoWOnLimit) {
		return newResult(true, "rate_limit_bypassed_by_pow", nil)
	}

	reason := fmt.Sprintf("rate_limit_exceeded:required_pow_%d", f.cfg.RequiredPoWOnLimit)
	return newResult(false, reason, nil)
}

func (f *EphemeralChatFilter) getLimiter(key string) *rate.Limiter {
	if limiter, ok := f.limiters.Get(key); ok {
		return limiter
	}
	limiter := rate.NewLimiter(rate.Limit(f.cfg.RateLimitRate), f.cfg.RateLimitBurst)
	f.limiters.Add(key, limiter)
	return limiter
}
