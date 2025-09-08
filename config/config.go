// config/config.go
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Log     LogConfig     `toml:"log"`
	DB      DBConfig      `toml:"database"`
	Strfry  StrfryConfig  `toml:"strfry"`
	Policy  PolicyConfig  `toml:"policy"`
	Filters FiltersConfig `toml:"filters"`
}

type LogLevel string

const (
	DebugLevel LogLevel = "debug"
	InfoLevel  LogLevel = "info"
	WarnLevel  LogLevel = "warn"
	ErrorLevel LogLevel = "error"
)

func (l *LogLevel) UnmarshalText(text []byte) error {
	v := string(text)
	switch LogLevel(v) {
	case DebugLevel, InfoLevel, WarnLevel, ErrorLevel:
		*l = LogLevel(v)
		return nil
	default:
		return fmt.Errorf("invalid log.level: %q (must be debug, info, warn, error)", v)
	}
}

func (l LogLevel) String() string { return string(l) }

func (l LogLevel) ToSlogLevel() slog.Level {
	switch l {
	case DebugLevel:
		return slog.LevelDebug
	case WarnLevel:
		return slog.LevelWarn
	case ErrorLevel:
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

type LogConfig struct {
	Level           LogLevel            `toml:"level"`
	RejectionLevels map[string]LogLevel `toml:"rejection_levels"`
}

type DBConfig struct {
	Path string `toml:"path"`
}

type StrfryConfig struct {
	ExecutablePath string `toml:"executable_path"`
	ConfigPath     string `toml:"config_path"`
}

type PolicyConfig struct {
	ModeratorPubKey string        `toml:"moderator_pubkey"`
	BanEmoji        string        `toml:"ban_emoji"`
	UnbanEmoji      string        `toml:"unban_emoji"`
	BanDuration     time.Duration `toml:"ban_duration"`
	AllowedKinds    []int         `toml:"allowed_kinds"`
	DeniedKinds     []int         `toml:"denied_kinds"`
}

type FiltersConfig struct {
	RateLimiter   RateLimiterConfig         `toml:"rate_limiter"`
	Freshness     FreshnessFilterConfig     `toml:"freshness"`
	Size          SizeFilterConfig          `toml:"size"`
	Tags          TagsFilterConfig          `toml:"tags"`
	Keywords      KeywordFilterConfig       `toml:"keywords"`
	Language      LanguageFilterConfig      `toml:"language"`
	EphemeralChat EphemeralChatFilterConfig `toml:"ephemeral_chat"`
	RepostAbuse   RepostAbuseFilterConfig   `toml:"repost_abuse"`
	BannedAuthor  BannedAuthorFilterConfig  `toml:"banned_author"`
	AutoBan       AutoBanFilterConfig       `toml:"autoban"`
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
		return fmt.Errorf("invalid filters.rate_limiter.by: %q (must be ip, pubkey, both)", v)
	}
}

func (m RateLimiterBy) String() string { return string(m) }

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

type FreshnessFilterConfig struct {
	MaxPast   time.Duration `toml:"max_past"`
	MaxFuture time.Duration `toml:"max_future"`
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
	CacheTTL              time.Duration `toml:"cache_ttl"`
	CountRejectAsActivity bool          `toml:"count_reject_as_activity"`
	RequireNIP21InQuote   bool          `toml:"require_nip21_in_quote"`
}

type BannedAuthorFilterConfig struct {
	CheckNIP26 bool `toml:"check_nip26"`
}

type AutoBanFilterConfig struct {
	Enabled           bool          `toml:"enabled"`
	MaxStrikes        int           `toml:"max_strikes"`
	StrikeWindow      time.Duration `toml:"strike_window"`
	BanDuration       time.Duration `toml:"ban_duration"`
	StrikesCacheSize  int           `toml:"strikes_cache_size"`
	CooldownCacheSize int           `toml:"cooldown_cache_size"`
	CooldownDuration  time.Duration `toml:"cooldown_duration"`
	BanTimeout        time.Duration `toml:"ban_timeout"`
	ExcludeFilters    []string      `toml:"exclude_filters_from_strikes"`
}

func findCommonElements(slice1, slice2 []int) []int {
	set := make(map[int]struct{})
	var common []int

	for _, item := range slice1 {
		set[item] = struct{}{}
	}

	for _, item := range slice2 {
		if _, found := set[item]; found {
			common = append(common, item)
		}
	}
	return common
}

func defaultConfig() *Config {
	return &Config{
		DB: DBConfig{
			Path: "./plugin-db",
		},
		Strfry: StrfryConfig{
			ExecutablePath: "/usr/local/bin/strfry",
			ConfigPath:     "/etc/strfry.conf",
		},
		Policy: PolicyConfig{
			BanEmoji:    "🔨",
			UnbanEmoji:  "🔓",
			BanDuration: 30 * 24 * time.Hour,
		},
	}
}

func (c *Config) validate() error {
	// --- [policy] ---
	if c.Policy.BanDuration <= 0 {
		return errors.New("policy.ban_duration must be a positive duration (e.g., '24h')")
	}
	if (c.Policy.BanEmoji != "" || c.Policy.UnbanEmoji != "") && c.Policy.ModeratorPubKey == "" {
		return errors.New("policy.moderator_pubkey must be set")
	}
	if common := findCommonElements(c.Policy.AllowedKinds, c.Policy.DeniedKinds); len(common) > 0 {
		return fmt.Errorf("policy.allowed_kinds and policy.denied_kinds must not contain common kinds: %v", common)
	}

	// --- [filters] ---

	// [filters.rate_limiter]
	if c.Filters.RateLimiter.Enabled {
		if c.Filters.RateLimiter.DefaultRate < 0 || c.Filters.RateLimiter.DefaultBurst <= 0 {
			return errors.New("filters.rate_limiter: default_rate and default_burst must be > 0 when enabled")
		}
		for i, rule := range c.Filters.RateLimiter.Rules {
			if rule.Rate < 0 || rule.Burst <= 0 {
				return fmt.Errorf("filters.rate_limiter.rule[%d] ('%s'): rate and burst must be > 0", i, rule.Description)
			}
		}
	}

	// [filters.freshness]
	if c.Filters.Freshness.MaxPast < 0 {
		return errors.New("filters.freshness.max_past must not be a negative duration")
	}
	if c.Filters.Freshness.MaxFuture < 0 {
		return errors.New("filters.freshness.max_future must not be a negative duration")
	}

	// [filters.size]
	if c.Filters.Size.DefaultMaxSize < 0 {
		return errors.New("filters.size.default_max_size_bytes must not be negative")
	}
	for i, rule := range c.Filters.Size.Rules {
		if rule.MaxSize < 0 {
			return fmt.Errorf("filters.size.rule[%d] ('%s'): max_size_bytes must not be negative", i, rule.Description)
		}
	}

	// [filters.tags]
	for i, rule := range c.Filters.Tags.Rules {
		if rule.MaxTags != nil && *rule.MaxTags < 0 {
			return fmt.Errorf("filters.tags.rule[%d] ('%s'): max_tags must not be negative", i, rule.Description)
		}
		for tag, count := range rule.MaxTagCounts {
			if count < 0 {
				return fmt.Errorf("filters.tags.rule[%d] ('%s'): max_tag_counts for tag '%s' must not be negative", i, rule.Description, tag)
			}
		}
	}

	// [filters.keywords]
	if c.Filters.Keywords.Enabled {
		for i, rule := range c.Filters.Keywords.Rules {
			if len(rule.Kinds) == 0 {
				return fmt.Errorf("filters.keywords.rule[%d] ('%s'): must specify kinds", i, rule.Description)
			}
			if len(rule.Words) == 0 && len(rule.Regexps) == 0 {
				return fmt.Errorf("filters.keywords.rule[%d] ('%s'): must contain at least one word or regexp", i, rule.Description)
			}
		}
	}

	// [filters.language]
	lang := c.Filters.Language
	if lang.Enabled {
		if len(lang.AllowedLanguages) == 0 {
			return errors.New("filters.language.allowed_languages must not be empty when enabled")
		}
		if len(lang.KindsToCheck) == 0 {
			return errors.New("filters.language.kinds_to_check must not be empty when enabled")
		}
		if lang.MinLengthForCheck < 0 {
			return errors.New("filters.language.min_length_for_check must not be negative")
		}
		if lang.ApprovedCacheTTL < 0 {
			return errors.New("filters.language.approved_cache_ttl must not be a negative duration")
		}
		if lang.ApprovedCacheSize < 0 {
			return errors.New("filters.language.approved_cache_size must not be negative")
		}
		if len(lang.PrimaryAcceptThreshold) > 0 {
			// Create a set for quick checking of allowed languages.
			allowedSet := make(map[string]struct{}, len(lang.AllowedLanguages))
			for _, allowed := range lang.AllowedLanguages {
				allowedSet[strings.ToLower(allowed)] = struct{}{}
			}

			for primary, similarMap := range lang.PrimaryAcceptThreshold {
				// Requirement 1: Each primary key must be in allowed_languages.
				if _, ok := allowedSet[strings.ToLower(primary)]; !ok {
					return fmt.Errorf(
						"filters.language.primary_accept_threshold: primary language '%s' is not in allowed_languages",
						primary,
					)
				}

				for similar, confidence := range similarMap {
					// Requirement 2: All confidence values must be in the [0.0, 1.0] range.
					if confidence < 0.0 || confidence > 1.0 {
						return fmt.Errorf(
							"filters.language.primary_accept_threshold['%s']: confidence for '%s' is out of range [0.0, 1.0], got %f",
							primary,
							similar,
							confidence,
						)
					}
				}
			}
		}
	}

	// [filters.ephemeral_chat]
	ec := c.Filters.EphemeralChat
	if ec.Enabled {
		if len(ec.Kinds) == 0 {
			return errors.New("filters.ephemeral_chat.kinds must not be empty when enabled")
		}
		if ec.MinDelay < 0 {
			return errors.New("filters.ephemeral_chat.min_delay_between_messages must not be negative")
		}
		if ec.MaxCapsRatio < 0.0 || ec.MaxCapsRatio > 1.0 {
			return errors.New("filters.ephemeral_chat.max_caps_ratio must be between 0.0 and 1.0")
		}
		if ec.MinLettersForCapsCheck <= 0 || ec.MaxWordLength <= 0 || ec.RequiredPoWOnLimit <= 0 {
			return errors.New("filters.ephemeral_chat: min_letters_for_caps_check, max_word_length, and required_pow_on_limit must be > 0 when enabled")
		}
		// This check can be 0 (to disable it), but not negative.
		if ec.MaxRepeatChars < 0 {
			return errors.New("filters.ephemeral_chat.max_character_repetitions must not be negative")
		}
	}

	// [filters.repost_abuse]
	ra := c.Filters.RepostAbuse
	if ra.Enabled {
		if ra.MaxRatio < 0.0 || ra.MaxRatio > 1.0 {
			return errors.New("filters.repost_abuse.max_ratio must be between 0.0 and 1.0")
		}
		if ra.MinEvents < 0 {
			return errors.New("filters.repost_abuse.min_events must not be negative")
		}
		if ra.ResetDuration < 0 {
			return errors.New("filters.repost_abuse.reset_duration must not be negative")
		}
		if ra.CacheTTL <= 0 {
			return errors.New("filters.repost_abuse.cache_ttl must be a positive duration")
		}
	}

	// [filters.autoban]
	ab := c.Filters.AutoBan
	if ab.Enabled {
		if ab.MaxStrikes <= 0 {
			return errors.New("filters.autoban.max_strikes must be > 0")
		}
		if ab.StrikeWindow <= 0 {
			return errors.New("filters.autoban.strike_window must be a positive duration")
		}
		if ab.BanDuration <= 0 {
			return errors.New("filters.autoban.ban_duration must be a positive duration")
		}
		if ab.StrikesCacheSize <= 0 {
			return errors.New("filters.autoban.strikes_cache_size must be > 0")
		}
		if ab.CooldownCacheSize <= 0 {
			return errors.New("filters.autoban.cooldown_cache_size must be > 0")
		}
		if ab.CooldownDuration <= 0 {
			return errors.New("filters.autoban.cooldown_duration must be a positive duration")
		}
		// BanTimeout: allow 0 (means use internal default), but forbid negatives.
		if ab.BanTimeout < 0 {
			return errors.New("filters.autoban.ban_timeout must not be negative")
		}
	}

	return nil
}

func Load(path string, useDefaults bool) (*Config, bool, error) {
	cfg := defaultConfig()
	defaultsUsed := false

	if _, err := toml.DecodeFile(path, cfg); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			if useDefaults {
				defaultsUsed = true
				if err := cfg.validate(); err != nil {
					return nil, true, err
				}
				return cfg, defaultsUsed, nil
			}
			return nil, false, fmt.Errorf("config file not found at %s", path)
		}
		return nil, false, fmt.Errorf("failed to load config file %s: %w", path, err)
	}

	if err := cfg.validate(); err != nil {
		return nil, false, err
	}
	return cfg, defaultsUsed, nil
}
