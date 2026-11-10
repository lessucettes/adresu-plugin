package policy

import (
	"context"
	"fmt"

	"fiatjaf.com/nostr"

	"github.com/lessucettes/adresu-plugin/pkg/adresu-kit/config"
	"github.com/lessucettes/adresu-plugin/pkg/adresu-kit/reputation"
)

const (
	// ReputationFilterName is the configuration and autoban key for this filter.
	ReputationFilterName = "ReputationFilter"
	// ReputationObservationKey carries a reputation.Assessment when observe
	// mode encounters an event that would have been rejected. The plugin
	// integration owns logging; the kit filter never creates a logger.
	ReputationObservationKey = "reputation_observation"
	// ReputationDiagnosticKey carries ReputationDiagnostic for a rejected or
	// would-reject assessment, keeping administrative details out of Reason.
	ReputationDiagnosticKey = "reputation_diagnostic"
)

// ReputationDiagnostic supplies numeric details to application-owned logging.
// ReputationObservationKey retains its separate Assessment value for callers.
type ReputationDiagnostic struct {
	Assessment   reputation.Assessment
	MinTrustRank float64
}

// ReputationFilter applies a local reputation snapshot to non-ephemeral
// events. It is intentionally policy-only: it never talks to the network and
// never computes scores itself.
type ReputationFilter struct {
	enabled      bool
	mode         string
	minTrustRank float64
	reader       reputation.Reader
}

// NewReputationFilter constructs the filter. A disabled filter does not need a
// reader; an enabled filter does. An empty mode is treated as observe for
// standalone callers that do not apply plugin defaults.
func NewReputationFilter(cfg *config.ReputationFilterConfig, reader reputation.Reader) (*ReputationFilter, error) {
	if cfg == nil {
		return nil, fmt.Errorf("reputation filter: config is required")
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("reputation filter: %w", err)
	}

	mode := config.NormalizeReputationMode(cfg.Mode)
	if cfg.Enabled && reader == nil {
		return nil, fmt.Errorf("reputation filter: an enabled filter requires a reputation reader")
	}

	return &ReputationFilter{
		enabled:      cfg.Enabled,
		mode:         mode,
		minTrustRank: cfg.MinTrustRank,
		reader:       reader,
	}, nil
}

// Match checks the author against the local snapshot. Unready snapshots,
// ephemeral events, and all disabled-filter cases fail open by accepting.
func (f *ReputationFilter) Match(_ context.Context, event *nostr.Event, meta map[string]any) (FilterResult, error) {
	newResult := NewResultFunc(ReputationFilterName)

	if !f.enabled {
		return newResult(true, "Filter is disabled.", nil)
	}
	// NIP-01 ephemeral events are 20000 <= kind < 30000. They are not part of
	// the reputation policy; every other kind is checked.
	if event.Kind >= 20000 && event.Kind < 30000 {
		return newResult(true, "Reputation checks do not apply to ephemeral events.", nil)
	}

	assessment := f.reader.Lookup(event.PubKey)
	if !assessment.Ready {
		return newResult(true, "Reputation snapshot is not ready; allowing the event.", nil)
	}

	wouldReject, reason := f.evaluate(assessment)
	if !wouldReject {
		return newResult(true, "Event passes reputation checks.", nil)
	}
	if meta != nil {
		meta[ReputationDiagnosticKey] = ReputationDiagnostic{
			Assessment: assessment, MinTrustRank: f.minTrustRank,
		}
	}

	if f.mode == config.ReputationModeObserve {
		if meta != nil {
			meta[ReputationObservationKey] = assessment
		}
		return newResult(true, "would reject: "+reason, nil)
	}

	return newResult(false, "restricted: "+reason, nil)
}

// evaluate applies the configured raw TrustRank minimum. The score is not a
// percentage and is not combined with any other rank.
func (f *ReputationFilter) evaluate(assessment reputation.Assessment) (bool, string) {
	if !assessment.Known {
		return true, "The event author is not in this relay's trusted network."
	}

	// Write the comparison as >= so a NaN reader value cannot slip
	// through; NaN < minimum is false but NaN >= minimum must be false too.
	if !(assessment.Score.TrustRank >= f.minTrustRank) {
		return true, "The event author's reputation does not meet this relay's requirements."
	}
	return false, ""
}
