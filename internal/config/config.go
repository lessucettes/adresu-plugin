package config

import (
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"math"
	"strings"
	"time"

	"fiatjaf.com/nostr"
	"github.com/BurntSushi/toml"
	kitconfig "github.com/lessucettes/adresu-plugin/pkg/adresu-kit/config"
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
}

type FiltersConfig struct {
	Kind          kitconfig.KindFilterConfig          `toml:"policy"`
	Emergency     kitconfig.EmergencyFilterConfig     `toml:"emergency"`
	RateLimiter   kitconfig.RateLimiterConfig         `toml:"rate_limiter"`
	Freshness     kitconfig.FreshnessFilterConfig     `toml:"freshness"`
	Size          kitconfig.SizeFilterConfig          `toml:"size"`
	Tags          kitconfig.TagsFilterConfig          `toml:"tags"`
	Keywords      kitconfig.KeywordFilterConfig       `toml:"keywords"`
	Language      kitconfig.LanguageFilterConfig      `toml:"language"`
	EphemeralChat kitconfig.EphemeralChatFilterConfig `toml:"ephemeral_chat"`
	RepostAbuse   kitconfig.RepostAbuseFilterConfig   `toml:"repost_abuse"`

	BannedAuthor BannedAuthorFilterConfig `toml:"banned_author"`
	AutoBan      AutoBanFilterConfig      `toml:"autoban"`
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

func isFinite(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0)
}

// isHexPubKey reports whether s encodes a valid Schnorr public key in hex.
// Moderation compares decoded key bytes, so uppercase hex is accepted too.
func isHexPubKey(s string) bool {
	if !nostr.IsValid32ByteHex(strings.ToLower(s)) {
		return false
	}
	_, err := nostr.PubKeyFromHex(s)
	return err == nil
}

// undecodedKeyNames returns the dotted names of TOML keys that did not map to
// any configuration field, in file order.
func undecodedKeyNames(md toml.MetaData) []string {
	keys := md.Undecoded()
	if len(keys) == 0 {
		return nil
	}
	names := make([]string, 0, len(keys))
	for _, key := range keys {
		names = append(names, key.String())
	}
	return names
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
		Filters: FiltersConfig{
			RateLimiter: kitconfig.RateLimiterConfig{
				// Without an explicit "by", the rate limiter would otherwise
				// accept every event when enabled.
				By: kitconfig.RateByBoth,
			},
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
	// A malformed key can never match a signed event's pubkey, so moderation
	// would silently stop working. Only enforce this while moderation is
	// active; an unused key is left untouched.
	if (c.Policy.BanEmoji != "" || c.Policy.UnbanEmoji != "") && !isHexPubKey(c.Policy.ModeratorPubKey) {
		return errors.New("policy.moderator_pubkey must be a 64-character hex public key")
	}
	if (c.Policy.BanEmoji != "" || c.Policy.UnbanEmoji != "") && c.Policy.BanEmoji == c.Policy.UnbanEmoji {
		return errors.New("policy.ban_emoji and policy.unban_emoji must not be identical")
	}
	if common := findCommonElements(c.Filters.Kind.AllowedKinds, c.Filters.Kind.DeniedKinds); len(common) > 0 {
		return fmt.Errorf("filters.policy.allowed_kinds and filters.policy.denied_kinds must not overlap: %v", common)
	}

	// --- [filters] ---

	// [filters.emergency]
	ef := c.Filters.Emergency
	if ef.Enabled {
		if !isFinite(ef.NewKeysRate) || ef.NewKeysRate <= 0 {
			return errors.New("filters.emergency.new_keys_rate must be finite and > 0")
		}
		if ef.NewKeysBurst < 0 {
			return errors.New("filters.emergency.new_keys_burst must be >= 0")
		}
		if ef.CacheSize <= 0 {
			return errors.New("filters.emergency.cache_size must be positive")
		}
		if ef.TTL <= 0 {
			return errors.New("filters.emergency.ttl must be a positive duration")
		}
		if ef.PerIP.Enabled {
			if !isFinite(ef.PerIP.Rate) || ef.PerIP.Rate <= 0 {
				return errors.New("filters.emergency.per_ip.rate must be finite and > 0")
			}
			if ef.PerIP.Burst < 0 {
				return errors.New("filters.emergency.per_ip.burst must be >= 0")
			}
			if ef.PerIP.CacheSize <= 0 {
				return errors.New("filters.emergency.per_ip.cache_size must be positive")
			}
			if ef.PerIP.TTL <= 0 {
				return errors.New("filters.emergency.per_ip.ttl must be a positive duration")
			}
			if p := ef.PerIP.IPv4Prefix; p < 0 || p > 32 {
				return errors.New("filters.emergency.per_ip.ipv4_prefix must be in [0..32]")
			}
			if p := ef.PerIP.IPv6Prefix; p < 0 || p > 128 {
				return errors.New("filters.emergency.per_ip.ipv6_prefix must be in [0..128]")
			}
		}
	}

	// [filters.rate_limiter]
	if c.Filters.RateLimiter.Enabled {
		if !isFinite(c.Filters.RateLimiter.DefaultRate) || c.Filters.RateLimiter.DefaultRate < 0 || c.Filters.RateLimiter.DefaultBurst <= 0 {
			return errors.New("filters.rate_limiter: default_rate must be finite and >= 0 and default_burst must be > 0")
		}
		for i, rule := range c.Filters.RateLimiter.Rules {
			if !isFinite(rule.Rate) || rule.Rate < 0 || rule.Burst <= 0 {
				return fmt.Errorf("filters.rate_limiter.rule[%d] ('%s'): rate must be finite and >= 0 and burst must be > 0", i, rule.Description)
			}
		}
	}

	// [filters.freshness]
	if c.Filters.Freshness.DefaultMaxPast < 0 {
		return errors.New("filters.freshness.default_max_past must not be a negative duration")
	}
	if c.Filters.Freshness.DefaultMaxFuture < 0 {
		return errors.New("filters.freshness.default_max_future must not be a negative duration")
	}
	// Validate each new rule.
	for i, rule := range c.Filters.Freshness.Rules {
		if len(rule.Kinds) == 0 {
			return fmt.Errorf("filters.freshness.rule[%d] ('%s'): must specify kinds", i, rule.Description)
		}
		if rule.MaxPast < 0 {
			return fmt.Errorf("filters.freshness.rule[%d] ('%s'): max_past must not be a negative duration", i, rule.Description)
		}
		if rule.MaxFuture < 0 {
			return fmt.Errorf("filters.freshness.rule[%d] ('%s'): max_future must not be a negative duration", i, rule.Description)
		}
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
					if !isFinite(confidence) || confidence < 0.0 || confidence > 1.0 {
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
		if !isFinite(ec.MaxCapsRatio) || ec.MaxCapsRatio < 0.0 || ec.MaxCapsRatio > 1.0 {
			return errors.New("filters.ephemeral_chat.max_caps_ratio must be between 0.0 and 1.0")
		}
		if ec.MinLettersForCapsCheck <= 0 || ec.MaxWordLength <= 0 || ec.RequiredPoWOnLimit <= 0 {
			return errors.New("filters.ephemeral_chat: min_letters_for_caps_check, max_word_length, and required_pow_on_limit must be > 0 when enabled")
		}
		// Zero rate and burst are valid and mean that every message needs PoW.
		if ec.RateLimitRate < 0 || !isFinite(ec.RateLimitRate) {
			return errors.New("filters.ephemeral_chat.rate_limit_rate must not be negative or non-finite")
		}
		if ec.RateLimitBurst < 0 {
			return errors.New("filters.ephemeral_chat.rate_limit_burst must not be negative")
		}
		// This check can be 0 (to disable it), but not negative.
		if ec.MaxRepeatChars < 0 {
			return errors.New("filters.ephemeral_chat.max_character_repetitions must not be negative")
		}
	}

	// [filters.repost_abuse]
	ra := c.Filters.RepostAbuse
	if ra.Enabled {
		if !isFinite(ra.MaxRatio) || ra.MaxRatio < 0.0 || ra.MaxRatio > 1.0 {
			return errors.New("filters.repost_abuse.max_ratio must be between 0.0 and 1.0")
		}
		if ra.MinEvents < 0 {
			return errors.New("filters.repost_abuse.min_events must not be negative")
		}
		if ra.ResetDuration < 0 {
			return errors.New("filters.repost_abuse.reset_duration must not be negative")
		}
		if ra.CacheSize <= 0 {
			return errors.New("filters.repost_abuse.cache_size must be positive")
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

	md, err := toml.DecodeFile(path, cfg)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			if !useDefaults {
				return nil, false, fmt.Errorf("config file not found at %s", path)
			}

			// Built-in defaults enable moderation reactions, but a moderator
			// pubkey can only come from a config file. Disable moderation so
			// that the documented -use-defaults mode can actually start.
			cfg.Policy.BanEmoji = ""
			cfg.Policy.UnbanEmoji = ""
			if err := cfg.validate(); err != nil {
				return nil, true, err
			}
			slog.Warn("Config file not found, running with built-in defaults; moderation is disabled", "path", path)
			return cfg, true, nil
		}
		return nil, false, fmt.Errorf("failed to load config file %s: %w", path, err)
	}

	// Never activate a configuration with silently missing policy settings.
	// On reload the caller keeps the previous configuration if Load fails.
	if keys := undecodedKeyNames(md); len(keys) > 0 {
		return nil, false, fmt.Errorf("unrecognized configuration keys in %s: %s", path, strings.Join(keys, ", "))
	}

	if err := cfg.validate(); err != nil {
		return nil, false, err
	}
	return cfg, false, nil
}
