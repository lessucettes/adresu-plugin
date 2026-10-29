package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	kitconfig "github.com/lessucettes/adresu-plugin/pkg/adresu-kit/config"
)

// writeConfig writes body to a temporary config.toml and returns its path.
func writeConfig(t *testing.T, body string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestLoadAppliesDefaultsAndDecodesSections(t *testing.T) {
	path := writeConfig(t, `
[log]
level = "debug"

[log.rejection_levels]
KindFilter = "debug"

[policy]
moderator_pubkey = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
ban_duration = "48h"

[filters.policy]
allowed_kinds = [0, 1]
denied_kinds = [4]

[filters.rate_limiter]
enabled = true
default_rate = 0.5
default_burst = 5
`)

	cfg, defaultsUsed, err := Load(path, false)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if defaultsUsed {
		t.Fatal("defaultsUsed = true for an existing config file")
	}

	if cfg.Log.Level != DebugLevel {
		t.Errorf("log.level = %q, want %q", cfg.Log.Level, DebugLevel)
	}
	if got := cfg.Log.RejectionLevels["KindFilter"]; got != DebugLevel {
		t.Errorf("rejection level for KindFilter = %q, want %q", got, DebugLevel)
	}
	if cfg.Policy.BanDuration != 48*time.Hour {
		t.Errorf("ban_duration = %v, want 48h", cfg.Policy.BanDuration)
	}
	if len(cfg.Filters.Kind.AllowedKinds) != 2 || cfg.Filters.Kind.AllowedKinds[0] != 0 || cfg.Filters.Kind.AllowedKinds[1] != 1 {
		t.Errorf("filters.policy.allowed_kinds = %v, want [0 1]", cfg.Filters.Kind.AllowedKinds)
	}
	if len(cfg.Filters.Kind.DeniedKinds) != 1 || cfg.Filters.Kind.DeniedKinds[0] != 4 {
		t.Errorf("filters.policy.denied_kinds = %v, want [4]", cfg.Filters.Kind.DeniedKinds)
	}

	// Fields absent from the file must keep their built-in defaults.
	if cfg.DB.Path != "./plugin-db" {
		t.Errorf("database.path = %q, want default %q", cfg.DB.Path, "./plugin-db")
	}
	if cfg.Strfry.ExecutablePath != "/usr/local/bin/strfry" {
		t.Errorf("strfry.executable_path = %q, want default", cfg.Strfry.ExecutablePath)
	}
	if cfg.Policy.BanEmoji != "🔨" {
		t.Errorf("ban_emoji = %q, want default 🔨", cfg.Policy.BanEmoji)
	}
}

func TestLoadDefaultsRateLimiterByToBoth(t *testing.T) {
	path := writeConfig(t, `
[policy]
moderator_pubkey = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

[filters.rate_limiter]
enabled = true
default_rate = 0.5
default_burst = 5
`)

	cfg, _, err := Load(path, false)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Filters.RateLimiter.By != kitconfig.RateByBoth {
		t.Fatalf("rate_limiter.by = %q, want %q when omitted", cfg.Filters.RateLimiter.By, kitconfig.RateByBoth)
	}
}

func TestLoadKeepsExplicitRateLimiterBy(t *testing.T) {
	path := writeConfig(t, `
[policy]
moderator_pubkey = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

[filters.rate_limiter]
enabled = true
by = "ip"
default_rate = 0.5
default_burst = 5
`)

	cfg, _, err := Load(path, false)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.Filters.RateLimiter.By; got != "ip" {
		t.Fatalf("rate_limiter.by = %q, want explicit %q", got, "ip")
	}
}

func TestLoadDecodesNestedFilterSections(t *testing.T) {
	path := writeConfig(t, `
[policy]
moderator_pubkey = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

[filters.emergency]
enabled = true
new_keys_rate = 10
new_keys_burst = 20
cache_size = 100
ttl = "10s"

[filters.emergency.per_ip]
enabled = true
rate = 5
burst = 10
cache_size = 100
ttl = "1m"
ipv4_prefix = 24
ipv6_prefix = 64

[filters.language]
enabled = true
allowed_languages = ["en"]
kinds_to_check = [1]
min_length_for_check = 20
approved_cache_ttl = "30m"
approved_cache_size = 1000

[filters.language.primary_accept_threshold.en]
default = 0.5

[[filters.tags.rule]]
description = "notes"
kinds = [1]
max_tags = 10
required_tags = ["e"]
max_tag_counts = { p = 4 }
`)

	cfg, _, err := Load(path, false)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if !cfg.Filters.Emergency.PerIP.Enabled || cfg.Filters.Emergency.PerIP.IPv4Prefix != 24 || cfg.Filters.Emergency.PerIP.IPv6Prefix != 64 {
		t.Errorf("filters.emergency.per_ip decoded as %+v", cfg.Filters.Emergency.PerIP)
	}
	if got := cfg.Filters.Language.PrimaryAcceptThreshold["en"]["default"]; got != 0.5 {
		t.Errorf("primary_accept_threshold[en][default] = %v, want 0.5", got)
	}
	if len(cfg.Filters.Tags.Rules) != 1 || cfg.Filters.Tags.Rules[0].MaxTagCounts["p"] != 4 {
		t.Errorf("filters.tags.rule decoded as %+v", cfg.Filters.Tags.Rules)
	}
}

func TestLoadMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist.toml")

	if _, _, err := Load(path, false); err == nil {
		t.Fatal("Load without useDefaults: expected an error for a missing file")
	}

	cfg, defaultsUsed, err := Load(path, true)
	if err != nil {
		t.Fatalf("Load with useDefaults: %v", err)
	}
	if !defaultsUsed {
		t.Fatal("defaultsUsed = false, want true")
	}
	if cfg.DB.Path != "./plugin-db" {
		t.Errorf("database.path = %q, want default %q", cfg.DB.Path, "./plugin-db")
	}
	// No moderator can exist without a config file, so moderation must be
	// disabled rather than making -use-defaults unusable.
	if cfg.Policy.BanEmoji != "" || cfg.Policy.UnbanEmoji != "" {
		t.Errorf("moderation emojis = %q/%q, want them disabled with built-in defaults", cfg.Policy.BanEmoji, cfg.Policy.UnbanEmoji)
	}
}

func TestLoadValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr string
	}{
		{
			name: "default emojis require moderator",
			body: `
[policy]
ban_duration = "24h"
`,
			wantErr: "policy.moderator_pubkey must be set",
		},
		{
			name: "identical emojis",
			body: `
[policy]
moderator_pubkey = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
ban_emoji = "x"
unban_emoji = "x"
`,
			wantErr: "must not be identical",
		},
		{
			name: "overlapping kinds",
			body: `
[policy]
moderator_pubkey = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

[filters.policy]
allowed_kinds = [1, 4]
denied_kinds = [4]
`,
			wantErr: "filters.policy.allowed_kinds and filters.policy.denied_kinds must not overlap",
		},
		{
			name: "negative ephemeral chat rate",
			body: `
[policy]
moderator_pubkey = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

[filters.ephemeral_chat]
enabled = true
kinds = [20000]
min_letters_for_caps_check = 20
max_word_length = 120
required_pow_on_limit = 12
rate_limit_rate = -1
rate_limit_burst = 5
`,
			wantErr: "rate_limit_rate must not be negative",
		},
		{
			name: "negative ephemeral chat burst",
			body: `
[policy]
moderator_pubkey = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

[filters.ephemeral_chat]
enabled = true
kinds = [20000]
min_letters_for_caps_check = 20
max_word_length = 120
required_pow_on_limit = 12
rate_limit_rate = 0.5
rate_limit_burst = -1
`,
			wantErr: "rate_limit_burst must not be negative",
		},
		{
			name: "invalid moderator pubkey",
			body: `
[policy]
moderator_pubkey = "not-a-hex-pubkey"
`,
			wantErr: "policy.moderator_pubkey must be a 64-character hex public key",
		},
		{
			name: "moderator pubkey is not a curve point",
			body: `
[policy]
moderator_pubkey = "0000000000000000000000000000000000000000000000000000000000000000"
`,
			wantErr: "policy.moderator_pubkey must be a 64-character hex public key",
		},
		{
			name: "invalid duration unit",
			body: `
[policy]
moderator_pubkey = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
ban_duration = "7d"
`,
			wantErr: "invalid duration",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := Load(writeConfig(t, tt.body), false)
			if err == nil {
				t.Fatalf("Load: expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Load error = %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoadRejectsUnrecognizedKeys(t *testing.T) {
	const moderator = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

	tests := []struct {
		name     string
		body     string
		wantKeys []string
	}{
		{
			name: "misplaced keys",
			body: `
[policy]
moderator_pubkey = "` + moderator + `"
allowed_kinds = [0, 1]
denied_kinds = [4]

[filters.freshness]
max_past = "24h"
max_future = "10m"
`,
			wantKeys: []string{
				"policy.allowed_kinds",
				"policy.denied_kinds",
				"filters.freshness.max_past",
				"filters.freshness.max_future",
			},
		},
		{
			name: "correctly placed keys are accepted",
			body: `
[policy]
moderator_pubkey = "` + moderator + `"

[filters.policy]
allowed_kinds = [0, 1]
denied_kinds = [4]

[filters.freshness]
default_max_past = "24h"
default_max_future = "10m"
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, _, err := Load(writeConfig(t, tt.body), false)
			if len(tt.wantKeys) == 0 {
				if err != nil || cfg == nil {
					t.Fatalf("valid config rejected: %v", err)
				}
				return
			}
			if err == nil || cfg != nil {
				t.Fatalf("invalid config returned cfg=%+v, err=%v; want only an error", cfg, err)
			}
			for _, want := range tt.wantKeys {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error does not mention unknown key %q: %v", want, err)
				}
			}
		})
	}
}

func TestLoadModerationDisabledWithoutEmojis(t *testing.T) {
	path := writeConfig(t, `
[policy]
ban_emoji = ""
unban_emoji = ""
`)

	cfg, _, err := Load(path, false)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Policy.ModeratorPubKey != "" {
		t.Errorf("moderator_pubkey = %q, want empty", cfg.Policy.ModeratorPubKey)
	}
}

func TestLoadRejectsNonFiniteFilterNumbers(t *testing.T) {
	tests := []struct{ name, body string }{
		{"emergency_rate", "[filters.emergency]\nenabled=true\nnew_keys_rate=VALUE\nnew_keys_burst=1\ncache_size=1\nttl=\"1h\"\n"},
		{"emergency_ip_rate", "[filters.emergency]\nenabled=true\nnew_keys_rate=1\nnew_keys_burst=1\ncache_size=1\nttl=\"1h\"\n[filters.emergency.per_ip]\nenabled=true\nrate=VALUE\nburst=1\ncache_size=1\nttl=\"1h\"\n"},
		{"default_rate", "[filters.rate_limiter]\nenabled=true\ndefault_rate=VALUE\ndefault_burst=1\n"},
		{"rule_rate", "[filters.rate_limiter]\nenabled=true\ndefault_rate=1\ndefault_burst=1\n[[filters.rate_limiter.rule]]\nkinds=[1]\nrate=VALUE\nburst=1\n"},
		{"caps_ratio", "[filters.ephemeral_chat]\nenabled=true\nkinds=[20000]\nmin_letters_for_caps_check=1\nmax_word_length=120\nrequired_pow_on_limit=1\nmax_caps_ratio=VALUE\n"},
		{"ephemeral_rate", "[filters.ephemeral_chat]\nenabled=true\nkinds=[20000]\nmin_letters_for_caps_check=1\nmax_word_length=120\nrequired_pow_on_limit=1\nrate_limit_rate=VALUE\n"},
		{"repost_ratio", "[filters.repost_abuse]\nenabled=true\nmax_ratio=VALUE\ncache_size=1\ncache_ttl=\"1h\"\n"},
		{"language_confidence", "[filters.language]\nenabled=true\nallowed_languages=[\"en\"]\nkinds_to_check=[1]\n[filters.language.primary_accept_threshold.en]\ndefault=VALUE\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := "[policy]\nban_emoji=\"\"\nunban_emoji=\"\"\n" + tt.body
			if _, _, err := Load(writeConfig(t, strings.ReplaceAll(body, "VALUE", "0.5")), false); err != nil {
				t.Fatalf("finite control config rejected: %v", err)
			}
			for _, value := range []string{"nan", "+inf", "-inf"} {
				t.Run(value, func(t *testing.T) {
					if _, _, err := Load(writeConfig(t, strings.ReplaceAll(body, "VALUE", value)), false); err == nil {
						t.Fatalf("non-finite %s silently bypassed validation", value)
					}
				})
			}
		})
	}
}

func TestLoadAllowsPoWOnlyEphemeralChat(t *testing.T) {
	path := writeConfig(t, `
[policy]
moderator_pubkey = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

[filters.ephemeral_chat]
enabled = true
kinds = [20000]
min_letters_for_caps_check = 20
max_word_length = 120
required_pow_on_limit = 12
rate_limit_rate = 0
rate_limit_burst = 0
`)

	cfg, _, err := Load(path, false)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Filters.EphemeralChat.Enabled {
		t.Error("ephemeral chat filter was not enabled")
	}
}
