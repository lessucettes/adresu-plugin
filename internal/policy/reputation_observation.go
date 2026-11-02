package policy

import (
	"log/slog"

	"fiatjaf.com/nostr"
	kitpolicy "github.com/lessucettes/adresu-plugin/pkg/adresu-kit/policy"
	kitrep "github.com/lessucettes/adresu-plugin/pkg/adresu-kit/reputation"
)

func logReputationObservation(event *nostr.Event, meta map[string]any) {
	assessment, ok := meta[kitpolicy.ReputationObservationKey].(kitrep.Assessment)
	if !ok {
		return
	}
	delete(meta, kitpolicy.ReputationObservationKey)
	// This is deliberately not an "Event rejected by filter" log record and has
	// no remote IP: observation must not feed the production Fail2Ban jails.
	slog.Info("Reputation observation", "would_reject", true,
		"event_id", event.ID.Hex(), "pubkey", event.PubKey.Hex(), "kind", int(event.Kind),
		"known", assessment.Known, "pagerank", assessment.Score.PageRank,
		"trustrank", assessment.Score.TrustRank)
}
