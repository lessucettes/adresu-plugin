package config

import (
	"fmt"
	"net/url"
	"strings"
	"time"
)

// maxReputationRelays bounds configured relay fan-out. Every relay can add
// connection, verification, and memory cost; eight is enough for redundancy
// without turning a small local collector into a relay crawler.
const maxReputationRelays = 8

// ReputationConfig configures the local follow-graph reputation collector.
// The collector builds a bounded graph from the configured relays and keeps a
// snapshot in the plugin's Badger database. The event path only reads that
// in-memory snapshot; it never waits for the network.
type ReputationConfig struct {
	Seeds           []string      `toml:"seeds"`
	Relays          []string      `toml:"relays"`
	DiscoverRelays  bool          `toml:"discover_relays"`
	DiscoveryRelays []string      `toml:"discovery_relays"`
	RefreshInterval time.Duration `toml:"refresh_interval"`
	MaxAge          time.Duration `toml:"max_age"`
	FetchTimeout    time.Duration `toml:"fetch_timeout"`
	MaxDepth        int           `toml:"max_depth"`
	MaxNodes        int           `toml:"max_nodes"`
	MaxEdges        int           `toml:"max_edges"`
	BatchSize       int           `toml:"batch_size"`
	MaxFollows      int           `toml:"max_follows"`
	MinCoverage     float64       `toml:"min_coverage"`
	Damping         float64       `toml:"damping"`
	Tolerance       float64       `toml:"tolerance"`
	MaxIterations   int           `toml:"max_iterations"`
}

// defaultReputationConfig returns a conservative local-graph configuration.
// Seeds and relays are intentionally unset: enabling the filter requires the
// operator to provide them explicitly.
func defaultReputationConfig() ReputationConfig {
	return ReputationConfig{
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
}

// validate checks the collector settings. It is called only when the
// reputation filter is enabled, so a disabled filter needs no seeds or relays.
func (c ReputationConfig) validate() error {
	if len(c.Seeds) == 0 {
		return fmt.Errorf("reputation.seeds must contain at least one seed public key when filters.reputation.enabled is true")
	}
	uniqueSeeds := make(map[string]struct{}, len(c.Seeds))
	for i, seed := range c.Seeds {
		if !isHexPubKey(seed) {
			return fmt.Errorf("reputation.seeds[%d] (%q) must be a 64-character hex public key", i, seed)
		}
		uniqueSeeds[strings.ToLower(seed)] = struct{}{}
	}

	if len(c.Relays) == 0 {
		return fmt.Errorf("reputation.relays must contain at least one ws:// or wss:// relay URL when filters.reputation.enabled is true")
	}
	if len(c.Relays) > maxReputationRelays {
		return fmt.Errorf("reputation.relays must contain at most %d relay URLs, got %d", maxReputationRelays, len(c.Relays))
	}
	for i, relay := range c.Relays {
		if !isWebSocketRelayURL(relay) {
			return fmt.Errorf("reputation.relays[%d] (%q) must be an explicit ws:// or wss:// URL with a host, no credentials, and no fragment", i, relay)
		}
	}

	if c.DiscoverRelays {
		if len(c.DiscoveryRelays) == 0 {
			return fmt.Errorf("reputation.discovery_relays must contain at least one ws:// or wss:// bootstrap URL when reputation.discover_relays is true")
		}
		if len(c.DiscoveryRelays) > maxReputationRelays {
			return fmt.Errorf("reputation.discovery_relays must contain at most %d relay URLs, got %d", maxReputationRelays, len(c.DiscoveryRelays))
		}
		for i, relay := range c.DiscoveryRelays {
			if !isWebSocketRelayURL(relay) {
				return fmt.Errorf("reputation.discovery_relays[%d] (%q) must be an explicit ws:// or wss:// URL with a host, no credentials, and no fragment", i, relay)
			}
		}
	}

	if c.MaxDepth < 1 || c.MaxDepth > 4 {
		return fmt.Errorf("reputation.max_depth must be between 1 and 4, got %d", c.MaxDepth)
	}
	if c.MaxNodes < 1 || c.MaxNodes > 1_000_000 {
		return fmt.Errorf("reputation.max_nodes must be between 1 and 1000000, got %d", c.MaxNodes)
	}
	if c.MaxNodes < len(uniqueSeeds) {
		return fmt.Errorf("reputation.max_nodes must accommodate all %d unique seeds", len(uniqueSeeds))
	}
	if c.MaxEdges < 1 || c.MaxEdges > 20_000_000 {
		return fmt.Errorf("reputation.max_edges must be between 1 and 20000000, got %d", c.MaxEdges)
	}
	if c.BatchSize < 1 || c.BatchSize > 200 {
		return fmt.Errorf("reputation.batch_size must be between 1 and 200, got %d", c.BatchSize)
	}
	if c.MaxFollows < 1 || c.MaxFollows > 50_000 {
		return fmt.Errorf("reputation.max_follows must be between 1 and 50000, got %d", c.MaxFollows)
	}

	if c.FetchTimeout <= 0 {
		return fmt.Errorf("reputation.fetch_timeout must be a positive duration")
	}
	if c.RefreshInterval <= 0 {
		return fmt.Errorf("reputation.refresh_interval must be a positive duration")
	}
	if c.MaxAge <= 0 {
		return fmt.Errorf("reputation.max_age must be a positive duration")
	}
	if c.MaxAge < c.RefreshInterval {
		return fmt.Errorf("reputation.max_age (%s) must be greater than or equal to refresh_interval (%s)", c.MaxAge, c.RefreshInterval)
	}
	if !isFinite(c.MinCoverage) || c.MinCoverage <= 0 || c.MinCoverage > 1 {
		return fmt.Errorf("reputation.min_coverage must be finite and in (0,1], got %v", c.MinCoverage)
	}
	if !isFinite(c.Damping) || c.Damping <= 0 || c.Damping >= 1 {
		return fmt.Errorf("reputation.damping must be finite and in (0,1), got %v", c.Damping)
	}
	if !isFinite(c.Tolerance) || c.Tolerance <= 0 {
		return fmt.Errorf("reputation.tolerance must be finite and greater than zero, got %v", c.Tolerance)
	}
	if c.MaxIterations < 1 || c.MaxIterations > 10_000 {
		return fmt.Errorf("reputation.max_iterations must be between 1 and 10000, got %d", c.MaxIterations)
	}

	return nil
}

// isWebSocketRelayURL accepts only explicit ws:// or wss:// URLs with a host.
// Credentials and fragments are rejected so the configured relay list cannot
// leak secrets or hide routing state. There is no scheme guessing or fallback
// to an outbox/event-provided relay.
func isWebSocketRelayURL(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil {
		return false
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "ws" && scheme != "wss" {
		return false
	}
	if parsed.Hostname() == "" || parsed.User != nil {
		return false
	}
	// Reject an empty fragment delimiter too, not just non-empty fragments.
	return parsed.Fragment == "" && !strings.Contains(raw, "#")
}
