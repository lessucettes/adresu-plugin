package config

import (
	"fmt"
	"math"
	"strings"
)

const (
	// ReputationModeObserve reports authors that would be rejected without
	// rejecting their events. It is the safe default.
	ReputationModeObserve = "observe"
	// ReputationModeEnforce rejects events from authors that are unknown in a
	// ready snapshot or fall below the configured TrustRank minimum.
	ReputationModeEnforce = "enforce"
)

// ReputationFilterConfig configures the reusable ReputationFilter. The filter
// owns policy only; collecting and ranking the graph is the caller's job.
type ReputationFilterConfig struct {
	Enabled      bool    `toml:"enabled"`
	Mode         string  `toml:"mode"`
	MinTrustRank float64 `toml:"min_trustrank"`
}

// DefaultReputationFilterConfig returns a disabled filter in observe mode.
func DefaultReputationFilterConfig() ReputationFilterConfig {
	return ReputationFilterConfig{Mode: ReputationModeObserve}
}

// NormalizeReputationMode maps the empty string to observe, trims surrounding
// whitespace, and lowercases the result. Unknown values are returned unchanged
// so Validate can report them.
func NormalizeReputationMode(mode string) string {
	normalized := strings.ToLower(strings.TrimSpace(mode))
	if normalized == "" {
		return ReputationModeObserve
	}
	return normalized
}

// Validate checks the mode and the TrustRank threshold. The threshold is a raw
// score in [0,1], not a percentage. Zero is valid and means graph membership
// only, which is not Sybil-resistant.
func (c ReputationFilterConfig) Validate() error {
	switch NormalizeReputationMode(c.Mode) {
	case ReputationModeObserve, ReputationModeEnforce:
	default:
		return fmt.Errorf("reputation.mode must be %q or %q, got %q", ReputationModeObserve, ReputationModeEnforce, c.Mode)
	}
	return validateReputationThreshold("min_trustrank", c.MinTrustRank)
}

func validateReputationThreshold(name string, value float64) error {
	if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || value > 1 {
		return fmt.Errorf("reputation.%s must be finite and in [0,1], got %v", name, value)
	}
	return nil
}
