// config/config.go
package config

import (
	"fmt"
	"time"
)

type EmergencyFilterConfig struct {
	Enabled      bool          `toml:"enabled"`
	NewKeysRate  float64       `toml:"new_keys_rate"`
	NewKeysBurst int           `toml:"new_keys_burst"`
	CacheSize    int           `toml:"cache_size"`
	TTL          time.Duration `toml:"ttl"`
	PerIP        struct {
		Enabled    bool          `toml:"enabled"`
		Rate       float64       `toml:"rate"`
		Burst      int           `toml:"burst"`
		CacheSize  int           `toml:"cache_size"`
		TTL        time.Duration `toml:"ttl"`
		IPv4Prefix int           `toml:"ipv4_prefix"`
		IPv6Prefix int           `toml:"ipv6_prefix"`
	} `toml:"per_ip"`
}

type RateLimiterBy string

const (
	RateByIP     RateLimiterBy = "ip"
	RateByPubKey RateLimiterBy = "pubkey"
	RateByBoth   RateLimiterBy = "both"
)

func (m *RateLimiterBy) UnmarshalText(text []byte) error {
	v := string(text)
	switch RateLimiterBy(v) {
	case RateByIP, RateByPubKey, RateByBoth, "":
		*m = RateLimiterBy(v)
		return nil
	default:
		return fmt.Errorf("invalid rate_limiter.by: %q (must be ip, pubkey, both)", v)
	}
}

type RateLimitRule struct {
	Description string  `toml:"description"`
	Kinds       []int   `toml:"kinds"`
	Rate        float64 `toml:"rate"`
	Burst       int     `toml:"burst"`
}

type RateLimiterConfig struct {
	Enabled      bool            `toml:"enabled"`
	By           RateLimiterBy   `toml:"by"`
	CacheSize    int             `toml:"cache_size"`
	TTL          time.Duration   `toml:"ttl"`
	DefaultRate  float64         `toml:"default_rate"`
	DefaultBurst int             `toml:"default_burst"`
	Rules        []RateLimitRule `toml:"rule"`
}

type KindFilterConfig struct {
	AllowedKinds []int `toml:"allowed_kinds"`
	DeniedKinds  []int `toml:"denied_kinds"`
}

type FreshnessRule struct {
	Kinds       []int         `toml:"kinds"`
	Description string        `toml:"description"`
	MaxPast     time.Duration `toml:"max_past"`
	MaxFuture   time.Duration `toml:"max_future"`
}

type FreshnessFilterConfig struct {
	DefaultMaxPast   time.Duration   `toml:"default_max_past"`
	DefaultMaxFuture time.Duration   `toml:"default_max_future"`
	Rules            []FreshnessRule `toml:"rule"`
}

type SizeRule struct {
	Description string `toml:"description"`
	Kinds       []int  `toml:"kinds"`
	MaxSize     int    `toml:"max_size_bytes"`
}

type SizeFilterConfig struct {
	DefaultMaxSize int        `toml:"default_max_size_bytes"`
	Rules          []SizeRule `toml:"rule"`
}

type TagRule struct {
	Kinds        []int          `toml:"kinds"`
	MaxTags      *int           `toml:"max_tags"`
	RequiredTags []string       `toml:"required_tags"`
	MaxTagCounts map[string]int `toml:"max_tag_counts"`
	Description  string         `toml:"description"`
}

type TagsFilterConfig struct {
	Rules []TagRule `toml:"rule"`
}

type KeywordRule struct {
	Description string   `toml:"description"`
	Kinds       []int    `toml:"kinds"`
	Words       []string `toml:"words"`
	Regexps     []string `toml:"regexps"`
}

type KeywordFilterConfig struct {
	Enabled bool          `toml:"enabled"`
	Rules   []KeywordRule `toml:"rule"`
}

type EphemeralChatFilterConfig struct {
	Enabled                bool          `toml:"enabled"`
	Kinds                  []int         `toml:"kinds"`
	MinDelay               time.Duration `toml:"min_delay_between_messages"`
	MaxCapsRatio           float64       `toml:"max_caps_ratio"`
	MinLettersForCapsCheck int           `toml:"min_letters_for_caps_check"`
	MaxRepeatChars         int           `toml:"max_character_repetitions"`
	MaxWordLength          int           `toml:"max_word_length"`
	BlockZalgo             bool          `toml:"block_zalgo_text"`
	CacheSize              int           `toml:"cache_size"`
	RateLimitRate          float64       `toml:"rate_limit_rate"`
	RateLimitBurst         int           `toml:"rate_limit_burst"`
	RequiredPoWOnLimit     int           `toml:"required_pow_on_limit"`
}

type LanguageFilterConfig struct {
	Enabled                bool                          `toml:"enabled"`
	AllowedLanguages       []string                      `toml:"allowed_languages"`
	KindsToCheck           []int                         `toml:"kinds_to_check"`
	MinLengthForCheck      int                           `toml:"min_length_for_check"`
	ApprovedCacheTTL       time.Duration                 `toml:"approved_cache_ttl"`
	ApprovedCacheSize      int                           `toml:"approved_cache_size"`
	PrimaryAcceptThreshold map[string]map[string]float64 `toml:"primary_accept_threshold"`
}

type RepostAbuseFilterConfig struct {
	Enabled               bool          `toml:"enabled"`
	MaxRatio              float64       `toml:"max_ratio"`
	MinEvents             int           `toml:"min_events"`
	ResetDuration         time.Duration `toml:"reset_duration"`
	CacheSize             int           `toml:"cache_size"`
	CacheTTL              time.Duration `toml:"cache_ttl"`
	CountRejectAsActivity bool          `toml:"count_reject_as_activity"`
	RequireNIP21InQuote   bool          `toml:"require_nip21_in_quote"`
}
