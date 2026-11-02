package config

import (
	"math"
	"strings"
	"testing"
	"time"

	kitconfig "github.com/lessucettes/adresu-plugin/pkg/adresu-kit/config"
)

const (
	reputationTestSeedA = "0101010101010101010101010101010101010101010101010101010101010101"
	reputationTestSeedB = "0202020202020202020202020202020202020202020202020202020202020202"

	validReputationTable = `
seeds = ["` + reputationTestSeedA + `", "` + reputationTestSeedB + `"]
relays = ["wss://relay.example.com", "ws://127.0.0.1:7777"]
discover_relays = false
refresh_interval = "1h"
max_age = "72h"
fetch_timeout = "10s"
max_depth = 2
max_nodes = 50000
max_edges = 1000000
batch_size = 64
max_follows = 5000
min_coverage = 0.8
damping = 0.85
tolerance = 0.00000001
max_iterations = 200
`
)

func enabledReputationConfig(reputationTable, filterTable string) string {
	return `
[policy]
ban_emoji = ""
unban_emoji = ""

[reputation]
` + reputationTable + `

[filters.reputation]
enabled = true
` + filterTable
}

func TestReputationDefaults(t *testing.T) {
	cfg := defaultConfig()

	want := ReputationConfig{
		RefreshInterval: time.Hour,
		MaxAge:          72 * time.Hour,
		FetchTimeout:    10 * time.Second,
		MaxDepth:        2,
		MaxNodes:        50_000,
		MaxEdges:        1_000_000,
		BatchSize:       64,
		MaxFollows:      5_000,
		MinCoverage:     0.8,
		Damping:         0.85,
		Tolerance:       1e-8,
		MaxIterations:   200,
	}
	if cfg.Reputation.RefreshInterval != want.RefreshInterval ||
		cfg.Reputation.MaxAge != want.MaxAge ||
		cfg.Reputation.FetchTimeout != want.FetchTimeout ||
		cfg.Reputation.MaxDepth != want.MaxDepth ||
		cfg.Reputation.MaxNodes != want.MaxNodes ||
		cfg.Reputation.MaxEdges != want.MaxEdges ||
		cfg.Reputation.BatchSize != want.BatchSize ||
		cfg.Reputation.MaxFollows != want.MaxFollows ||
		cfg.Reputation.MinCoverage != want.MinCoverage ||
		cfg.Reputation.Damping != want.Damping ||
		cfg.Reputation.Tolerance != want.Tolerance ||
		cfg.Reputation.MaxIterations != want.MaxIterations {
		t.Fatalf("reputation defaults = %+v, want %+v", cfg.Reputation, want)
	}
	if len(cfg.Reputation.Seeds) != 0 || len(cfg.Reputation.Relays) != 0 {
		t.Fatalf("seeds/relays = %v/%v, want unset", cfg.Reputation.Seeds, cfg.Reputation.Relays)
	}
	if cfg.Reputation.DiscoverRelays || len(cfg.Reputation.DiscoveryRelays) != 0 {
		t.Fatalf("discovery = %t/%v, want disabled", cfg.Reputation.DiscoverRelays, cfg.Reputation.DiscoveryRelays)
	}

	if cfg.Filters.Reputation.Enabled {
		t.Fatal("reputation filter is enabled by default")
	}
	if cfg.Filters.Reputation.Mode != kitconfig.ReputationModeObserve {
		t.Fatalf("reputation mode = %q, want %q", cfg.Filters.Reputation.Mode, kitconfig.ReputationModeObserve)
	}
	if cfg.Filters.Reputation.MinPageRank != 0 || cfg.Filters.Reputation.MinTrustRank != 0 {
		t.Fatalf("reputation thresholds = %v/%v, want zero", cfg.Filters.Reputation.MinPageRank, cfg.Filters.Reputation.MinTrustRank)
	}
}

func TestReputationLoadsEnabledConfiguration(t *testing.T) {
	path := writeConfig(t, `
[policy]
ban_emoji = ""
unban_emoji = ""

[reputation]
seeds = ["`+reputationTestSeedA+`"]
relays = ["wss://relay.example.com/", "ws://127.0.0.1:7777"]
refresh_interval = "2h"
max_age = "96h"
fetch_timeout = "5s"
max_depth = 3
max_nodes = 1000
max_edges = 2000
batch_size = 32
max_follows = 100
min_coverage = 0.5
damping = 0.9
tolerance = 0.000000001
max_iterations = 300

[filters.reputation]
enabled = true
mode = "enforce"
min_pagerank = 0.001
min_trustrank = 0.002
`)

	cfg, _, err := Load(path, false)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if len(cfg.Reputation.Seeds) != 1 || cfg.Reputation.Seeds[0] != reputationTestSeedA {
		t.Errorf("seeds = %v, want [%s]", cfg.Reputation.Seeds, reputationTestSeedA)
	}
	if len(cfg.Reputation.Relays) != 2 || cfg.Reputation.Relays[0] != "wss://relay.example.com/" {
		t.Errorf("relays = %v", cfg.Reputation.Relays)
	}
	if cfg.Reputation.RefreshInterval != 2*time.Hour || cfg.Reputation.MaxAge != 96*time.Hour {
		t.Errorf("refresh_interval/max_age = %v/%v", cfg.Reputation.RefreshInterval, cfg.Reputation.MaxAge)
	}
	if cfg.Reputation.FetchTimeout != 5*time.Second || cfg.Reputation.MaxDepth != 3 {
		t.Errorf("fetch_timeout/max_depth = %v/%d", cfg.Reputation.FetchTimeout, cfg.Reputation.MaxDepth)
	}
	if cfg.Reputation.MaxNodes != 1000 || cfg.Reputation.MaxEdges != 2000 || cfg.Reputation.BatchSize != 32 || cfg.Reputation.MaxFollows != 100 {
		t.Errorf("bounded graph settings = %+v", cfg.Reputation)
	}
	if cfg.Reputation.MinCoverage != 0.5 || cfg.Reputation.Damping != 0.9 || cfg.Reputation.Tolerance != 1e-9 || cfg.Reputation.MaxIterations != 300 {
		t.Errorf("ranking settings = %+v", cfg.Reputation)
	}
	if !cfg.Filters.Reputation.Enabled || cfg.Filters.Reputation.Mode != kitconfig.ReputationModeEnforce {
		t.Errorf("filter config = %+v", cfg.Filters.Reputation)
	}
	if cfg.Filters.Reputation.MinPageRank != 0.001 || cfg.Filters.Reputation.MinTrustRank != 0.002 {
		t.Errorf("thresholds = %v/%v", cfg.Filters.Reputation.MinPageRank, cfg.Filters.Reputation.MinTrustRank)
	}
}

func TestReputationLoadsDiscoverRelaysConfiguration(t *testing.T) {
	table := strings.Replace(validReputationTable, "discover_relays = false", `discover_relays = true
discovery_relays = ["wss://purplepag.es", "ws://127.0.0.1:7778"]`, 1)
	path := writeConfig(t, enabledReputationConfig(table, ""))

	cfg, _, err := Load(path, false)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.Reputation.DiscoverRelays || len(cfg.Reputation.DiscoveryRelays) != 2 {
		t.Fatalf("discovery = %t/%v", cfg.Reputation.DiscoverRelays, cfg.Reputation.DiscoveryRelays)
	}
	if cfg.Reputation.DiscoveryRelays[0] != "wss://purplepag.es" {
		t.Fatalf("discovery relays = %v", cfg.Reputation.DiscoveryRelays)
	}
}

func TestReputationDoesNotValidateDiscoveryRelaysWhenDisabled(t *testing.T) {
	table := validReputationTable + "\ndiscovery_relays = [\"https://not-a-relay.example\"]\n"
	path := writeConfig(t, enabledReputationConfig(table, ""))
	if _, _, err := Load(path, false); err != nil {
		t.Fatalf("disabled discovery configuration was rejected: %v", err)
	}
}

func TestReputationDisabledSkipsCollectorValidation(t *testing.T) {
	path := writeConfig(t, `
[policy]
ban_emoji = ""
unban_emoji = ""

[reputation]
seeds = ["not-a-pubkey"]
relays = ["https://relay.example.com"]
max_depth = 99
min_coverage = 4

[filters.reputation]
enabled = false
mode = "observe"
min_pagerank = 0
min_trustrank = 0
`)

	if _, _, err := Load(path, false); err != nil {
		t.Fatalf("disabled reputation config was rejected: %v", err)
	}
}

func TestReputationRejectsInvalidFilterConfigWhenDisabled(t *testing.T) {
	path := writeConfig(t, `
[policy]
ban_emoji = ""
unban_emoji = ""

[filters.reputation]
enabled = false
mode = "not-a-mode"
min_pagerank = -1
`)

	_, _, err := Load(path, false)
	if err == nil {
		t.Fatal("disabled filter with an invalid mode was accepted")
	}
	if !strings.Contains(err.Error(), "reputation.mode") && !strings.Contains(err.Error(), "reputation.min_pagerank") {
		t.Fatalf("error = %q, want a reputation filter configuration error", err)
	}
}

func TestReputationRejectsInvalidCollectorConfig(t *testing.T) {
	nineRelays := `relays = ["wss://r1.example.com", "wss://r2.example.com", "wss://r3.example.com", "wss://r4.example.com", "wss://r5.example.com", "wss://r6.example.com", "wss://r7.example.com", "wss://r8.example.com", "wss://r9.example.com"]`

	tests := []struct {
		name string
		old  string
		new  string
		want string
	}{
		{"missing seeds", `seeds = ["` + reputationTestSeedA + `", "` + reputationTestSeedB + `"]`, `seeds = []`, "reputation.seeds"},
		{"invalid seed", `seeds = ["` + reputationTestSeedA + `", "` + reputationTestSeedB + `"]`, `seeds = ["not-a-key"]`, "reputation.seeds[0]"},
		{"missing relays", `relays = ["wss://relay.example.com", "ws://127.0.0.1:7777"]`, `relays = []`, "reputation.relays"},
		{"too many relays", `relays = ["wss://relay.example.com", "ws://127.0.0.1:7777"]`, nineRelays, "at most 8 relay URLs"},
		{"http relay", `relays = ["wss://relay.example.com", "ws://127.0.0.1:7777"]`, `relays = ["https://relay.example.com"]`, "reputation.relays[0]"},
		{"relay without host", `relays = ["wss://relay.example.com", "ws://127.0.0.1:7777"]`, `relays = ["ws:///path"]`, "reputation.relays[0]"},
		{"relay with credentials", `relays = ["wss://relay.example.com", "ws://127.0.0.1:7777"]`, `relays = ["wss://user:pass@relay.example.com"]`, "reputation.relays[0]"},
		{"relay with fragment", `relays = ["wss://relay.example.com", "ws://127.0.0.1:7777"]`, `relays = ["wss://relay.example.com/#section"]`, "reputation.relays[0]"},
		{"relay with empty fragment", `relays = ["wss://relay.example.com", "ws://127.0.0.1:7777"]`, `relays = ["wss://relay.example.com/#"]`, "reputation.relays[0]"},
		{"discovery without bootstraps", `discover_relays = false`, `discover_relays = true`, "reputation.discovery_relays"},
		{"too many discovery relays", `discover_relays = false`, `discover_relays = true
discovery_relays = ["wss://r1.example.com", "wss://r2.example.com", "wss://r3.example.com", "wss://r4.example.com", "wss://r5.example.com", "wss://r6.example.com", "wss://r7.example.com", "wss://r8.example.com", "wss://r9.example.com"]`, "at most 8 relay URLs"},
		{"http discovery relay", `discover_relays = false`, `discover_relays = true
discovery_relays = ["https://indexer.example.com"]`, "reputation.discovery_relays[0]"},
		{"discovery relay with credentials", `discover_relays = false`, `discover_relays = true
discovery_relays = ["wss://user:pass@indexer.example.com"]`, "reputation.discovery_relays[0]"},
		{"discovery relay with fragment", `discover_relays = false`, `discover_relays = true
discovery_relays = ["wss://indexer.example.com/#read"]`, "reputation.discovery_relays[0]"},
		{"depth zero", `max_depth = 2`, `max_depth = 0`, "reputation.max_depth"},
		{"depth too high", `max_depth = 2`, `max_depth = 5`, "reputation.max_depth"},
		{"nodes zero", `max_nodes = 50000`, `max_nodes = 0`, "reputation.max_nodes"},
		{"seeds exceed nodes", `max_nodes = 50000`, `max_nodes = 1`, "reputation.max_nodes"},
		{"nodes too high", `max_nodes = 50000`, `max_nodes = 1000001`, "reputation.max_nodes"},
		{"edges zero", `max_edges = 1000000`, `max_edges = 0`, "reputation.max_edges"},
		{"edges too high", `max_edges = 1000000`, `max_edges = 20000001`, "reputation.max_edges"},
		{"batch zero", `batch_size = 64`, `batch_size = 0`, "reputation.batch_size"},
		{"batch too high", `batch_size = 64`, `batch_size = 201`, "reputation.batch_size"},
		{"follows zero", `max_follows = 5000`, `max_follows = 0`, "reputation.max_follows"},
		{"follows too high", `max_follows = 5000`, `max_follows = 50001`, "reputation.max_follows"},
		{"fetch timeout zero", `fetch_timeout = "10s"`, `fetch_timeout = "0s"`, "reputation.fetch_timeout"},
		{"refresh zero", `refresh_interval = "1h"`, `refresh_interval = "0s"`, "reputation.refresh_interval"},
		{"max age zero", `max_age = "72h"`, `max_age = "0s"`, "reputation.max_age"},
		{"max age below refresh", `max_age = "72h"`, `max_age = "30m"`, "greater than or equal to refresh_interval"},
		{"coverage zero", `min_coverage = 0.8`, `min_coverage = 0`, "reputation.min_coverage"},
		{"coverage above one", `min_coverage = 0.8`, `min_coverage = 1.01`, "reputation.min_coverage"},
		{"damping zero", `damping = 0.85`, `damping = 0`, "reputation.damping"},
		{"damping one", `damping = 0.85`, `damping = 1`, "reputation.damping"},
		{"tolerance zero", `tolerance = 0.00000001`, `tolerance = 0`, "reputation.tolerance"},
		{"iterations zero", `max_iterations = 200`, `max_iterations = 0`, "reputation.max_iterations"},
		{"iterations too high", `max_iterations = 200`, `max_iterations = 10001`, "reputation.max_iterations"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reputationTable := strings.Replace(validReputationTable, test.old, test.new, 1)
			if reputationTable == validReputationTable {
				t.Fatalf("test setup did not replace %q", test.old)
			}

			path := writeConfig(t, enabledReputationConfig(reputationTable, ""))
			_, _, err := Load(path, false)
			if err == nil {
				t.Fatal("invalid reputation configuration was accepted")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %q, want it to mention %q", err, test.want)
			}
		})
	}
}

func TestReputationRejectsInvalidFilterConfig(t *testing.T) {
	tests := []struct {
		name   string
		filter string
		want   string
	}{
		{"unknown mode", `mode = "bogus"`, "reputation.mode"},
		{"negative pagerank", `min_pagerank = -0.1`, "reputation.min_pagerank"},
		{"trustrank above one", `min_trustrank = 1.1`, "reputation.min_trustrank"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := writeConfig(t, enabledReputationConfig(validReputationTable, test.filter))
			_, _, err := Load(path, false)
			if err == nil {
				t.Fatal("invalid reputation filter configuration was accepted")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %q, want it to mention %q", err, test.want)
			}
		})
	}
}

func TestReputationRejectsNonFiniteThresholds(t *testing.T) {
	tests := []struct {
		name string
		set  func(*kitconfig.ReputationFilterConfig)
	}{
		{"nan pagerank", func(cfg *kitconfig.ReputationFilterConfig) { cfg.MinPageRank = math.NaN() }},
		{"infinite trustrank", func(cfg *kitconfig.ReputationFilterConfig) { cfg.MinTrustRank = math.Inf(1) }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := defaultConfig()
			cfg.Policy.BanEmoji = ""
			cfg.Policy.UnbanEmoji = ""
			cfg.Reputation.Seeds = []string{reputationTestSeedA}
			cfg.Reputation.Relays = []string{"wss://relay.example.com"}
			cfg.Filters.Reputation.Enabled = true
			test.set(&cfg.Filters.Reputation)

			if err := cfg.validate(); err == nil {
				t.Fatal("non-finite threshold was accepted")
			}
		})
	}
}

func TestReputationAcceptsBoundaryValues(t *testing.T) {
	path := writeConfig(t, `
[policy]
ban_emoji = ""
unban_emoji = ""

[reputation]
seeds = ["`+reputationTestSeedA+`"]
relays = [
  "wss://r1.example.com",
  "wss://r2.example.com",
  "wss://r3.example.com",
  "wss://r4.example.com",
  "wss://r5.example.com",
  "wss://r6.example.com",
  "wss://r7.example.com",
  "wss://r8.example.com",
]
refresh_interval = "1h"
max_age = "1h"
fetch_timeout = "1ns"
max_depth = 4
max_nodes = 1000000
max_edges = 20000000
batch_size = 200
max_follows = 50000
min_coverage = 1
damping = 0.999
tolerance = 0.000000000001
max_iterations = 10000

[filters.reputation]
enabled = true
mode = "observe"
min_pagerank = 0
min_trustrank = 1
`)

	if _, _, err := Load(path, false); err != nil {
		t.Fatalf("boundary reputation configuration was rejected: %v", err)
	}
}
