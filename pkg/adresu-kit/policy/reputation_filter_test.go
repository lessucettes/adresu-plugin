package policy

import (
	"context"
	"math"
	"strings"
	"testing"

	"fiatjaf.com/nostr"

	kitconfig "github.com/lessucettes/adresu-plugin/pkg/adresu-kit/config"
	"github.com/lessucettes/adresu-plugin/pkg/adresu-kit/reputation"
)

type fakeReputationReader struct {
	assessment reputation.Assessment
	calls      int
	lastPubKey nostr.PubKey
}

func (r *fakeReputationReader) Lookup(pubkey nostr.PubKey) reputation.Assessment {
	r.calls++
	r.lastPubKey = pubkey
	return r.assessment
}

func matchReputation(t *testing.T, filter *ReputationFilter, kind nostr.Kind, pubkey nostr.PubKey, meta map[string]any) FilterResult {
	t.Helper()

	result, err := filter.Match(context.Background(), &nostr.Event{Kind: kind, PubKey: pubkey}, meta)
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	return result
}

func TestReputationFilterDisabledAcceptsWithoutReader(t *testing.T) {
	filter, err := NewReputationFilter(&kitconfig.ReputationFilterConfig{}, nil)
	if err != nil {
		t.Fatalf("NewReputationFilter: %v", err)
	}

	result := matchReputation(t, filter, nostr.KindTextNote, fixturePubKey(1), nil)
	if !result.Allowed {
		t.Fatalf("disabled filter rejected an event: %s", result.Reason)
	}
	if result.Filter != ReputationFilterName {
		t.Fatalf("filter name = %q, want %q", result.Filter, ReputationFilterName)
	}
}

func TestReputationFilterEnabledRequiresReader(t *testing.T) {
	_, err := NewReputationFilter(&kitconfig.ReputationFilterConfig{Enabled: true}, nil)
	if err == nil {
		t.Fatal("enabled filter with a nil reader was accepted")
	}
}

func TestReputationFilterRejectsNilConfig(t *testing.T) {
	if _, err := NewReputationFilter(nil, nil); err == nil {
		t.Fatal("nil config was accepted")
	}
}

func TestReputationFilterValidatesConfig(t *testing.T) {
	reader := &fakeReputationReader{}
	tests := []struct {
		name    string
		cfg     kitconfig.ReputationFilterConfig
		wantErr string
	}{
		{"unknown mode", kitconfig.ReputationFilterConfig{Enabled: true, Mode: "bogus"}, "mode"},
		{"negative pagerank", kitconfig.ReputationFilterConfig{Enabled: true, MinPageRank: -0.01}, "min_pagerank"},
		{"trustrank above one", kitconfig.ReputationFilterConfig{Enabled: true, MinTrustRank: 1.01}, "min_trustrank"},
		{"nan pagerank", kitconfig.ReputationFilterConfig{Enabled: true, MinPageRank: math.NaN()}, "min_pagerank"},
		{"infinite trustrank", kitconfig.ReputationFilterConfig{Enabled: true, MinTrustRank: math.Inf(1)}, "min_trustrank"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := NewReputationFilter(&test.cfg, reader)
			if err == nil {
				t.Fatal("invalid config was accepted")
			}
			if !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %q, want it to mention %q", err, test.wantErr)
			}
		})
	}
}

func TestReputationFilterEmptyModeDefaultsToObserve(t *testing.T) {
	pubkey := fixturePubKey(2)
	reader := &fakeReputationReader{assessment: reputation.Assessment{Ready: true}}
	filter, err := NewReputationFilter(&kitconfig.ReputationFilterConfig{Enabled: true}, reader)
	if err != nil {
		t.Fatalf("NewReputationFilter: %v", err)
	}

	meta := map[string]any{}
	result := matchReputation(t, filter, nostr.KindTextNote, pubkey, meta)
	if !result.Allowed {
		t.Fatalf("observe mode rejected an unknown author: %s", result.Reason)
	}
	if _, ok := meta[ReputationObservationKey].(reputation.Assessment); !ok {
		t.Fatalf("meta[%q] = %#v, want a reputation.Assessment", ReputationObservationKey, meta[ReputationObservationKey])
	}
	if reader.lastPubKey != pubkey {
		t.Fatalf("Lookup received %s, want %s", reader.lastPubKey, pubkey)
	}
}

func TestReputationFilterEphemeralKindsBypass(t *testing.T) {
	reader := &fakeReputationReader{assessment: reputation.Assessment{
		Ready: true,
		Known: true,
		Score: reputation.Score{PageRank: 0.0, TrustRank: 0.0},
	}}
	filter, err := NewReputationFilter(&kitconfig.ReputationFilterConfig{
		Enabled:      true,
		Mode:         kitconfig.ReputationModeEnforce,
		MinPageRank:  0.5,
		MinTrustRank: 0.5,
	}, reader)
	if err != nil {
		t.Fatalf("NewReputationFilter: %v", err)
	}

	for _, kind := range []nostr.Kind{20000, 25000, 29999} {
		before := reader.calls
		result := matchReputation(t, filter, kind, fixturePubKey(3), nil)
		if !result.Allowed {
			t.Errorf("ephemeral kind %d was rejected: %s", kind, result.Reason)
		}
		if reader.calls != before {
			t.Errorf("ephemeral kind %d triggered a snapshot lookup", kind)
		}
	}

	for _, kind := range []nostr.Kind{19999, 30000} {
		result := matchReputation(t, filter, kind, fixturePubKey(3), nil)
		if result.Allowed {
			t.Errorf("non-ephemeral kind %d was allowed", kind)
		}
		if !strings.HasPrefix(result.Reason, "restricted: ") {
			t.Errorf("kind %d reason = %q, want a 'restricted: ' prefix", kind, result.Reason)
		}
	}
}

func TestReputationFilterUnreadySnapshotPasses(t *testing.T) {
	reader := &fakeReputationReader{assessment: reputation.Assessment{Ready: false}}
	filter, err := NewReputationFilter(&kitconfig.ReputationFilterConfig{
		Enabled:      true,
		Mode:         kitconfig.ReputationModeEnforce,
		MinPageRank:  0.5,
		MinTrustRank: 0.5,
	}, reader)
	if err != nil {
		t.Fatalf("NewReputationFilter: %v", err)
	}

	meta := map[string]any{}
	result := matchReputation(t, filter, nostr.KindTextNote, fixturePubKey(4), meta)
	if !result.Allowed {
		t.Fatalf("unready snapshot rejected an event: %s", result.Reason)
	}
	if !strings.Contains(result.Reason, "not ready") {
		t.Fatalf("reason = %q, want it to mention the snapshot state", result.Reason)
	}
	if len(meta) != 0 {
		t.Fatalf("unready snapshot produced observation metadata: %#v", meta)
	}
}

func TestReputationFilterEnforceUnknownAuthor(t *testing.T) {
	reader := &fakeReputationReader{assessment: reputation.Assessment{Ready: true, Known: false}}
	filter, err := NewReputationFilter(&kitconfig.ReputationFilterConfig{
		Enabled: true,
		Mode:    kitconfig.ReputationModeEnforce,
	}, reader)
	if err != nil {
		t.Fatalf("NewReputationFilter: %v", err)
	}

	meta := map[string]any{}
	result := matchReputation(t, filter, nostr.KindTextNote, fixturePubKey(5), meta)
	if result.Allowed {
		t.Fatal("enforce mode allowed an author missing from a ready snapshot")
	}
	if !strings.HasPrefix(result.Reason, "restricted: ") {
		t.Fatalf("reason = %q, want a 'restricted: ' prefix", result.Reason)
	}
	if result.Reason != "restricted: The event author is not in this relay's trusted network." {
		t.Fatalf("reason = %q, want it to explain the unknown author", result.Reason)
	}
	if _, exists := meta[ReputationObservationKey]; exists {
		t.Fatalf("enforce rejection produced observation metadata: %#v", meta)
	}
	diagnostic, ok := meta[ReputationDiagnosticKey].(ReputationDiagnostic)
	if !ok || diagnostic.Assessment != reader.assessment || diagnostic.MinPageRank != 0 || diagnostic.MinTrustRank != 0 {
		t.Fatalf("enforce diagnostic = %#v, want the assessment and configured minima", meta)
	}
}

func TestReputationFilterObserveRecordsWouldReject(t *testing.T) {
	assessment := reputation.Assessment{
		Ready: true,
		Known: true,
		Score: reputation.Score{PageRank: 0.1, TrustRank: 0.15},
	}
	reader := &fakeReputationReader{assessment: assessment}
	filter, err := NewReputationFilter(&kitconfig.ReputationFilterConfig{
		Enabled:      true,
		Mode:         kitconfig.ReputationModeObserve,
		MinPageRank:  0.2,
		MinTrustRank: 0.25,
	}, reader)
	if err != nil {
		t.Fatalf("NewReputationFilter: %v", err)
	}

	meta := map[string]any{}
	result := matchReputation(t, filter, nostr.KindTextNote, fixturePubKey(6), meta)
	if !result.Allowed {
		t.Fatalf("observe mode rejected an event: %s", result.Reason)
	}
	if !strings.HasPrefix(result.Reason, "would reject: ") {
		t.Fatalf("reason = %q, want a 'would reject: ' prefix", result.Reason)
	}
	observation, ok := meta[ReputationObservationKey].(reputation.Assessment)
	if !ok {
		t.Fatalf("meta[%q] = %#v, want a reputation.Assessment", ReputationObservationKey, meta[ReputationObservationKey])
	}
	if observation != assessment {
		t.Fatalf("observation = %+v, want %+v", observation, assessment)
	}
}

func TestReputationFilterEnforceRequiresBothRawScores(t *testing.T) {
	tests := []struct {
		name      string
		pageRank  float64
		trustRank float64
		allowed   bool
	}{
		{"both exactly at minimum", 0.10, 0.20, true},
		{"both above minimum", 0.11, 0.21, true},
		{"pagerank below", 0.09, 0.20, false},
		{"trustrank below", 0.10, 0.19, false},
		{"both below", 0.09, 0.19, false},
		{"nan pagerank", math.NaN(), 0.20, false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := &fakeReputationReader{assessment: reputation.Assessment{
				Ready: true,
				Known: true,
				Score: reputation.Score{PageRank: test.pageRank, TrustRank: test.trustRank},
			}}
			filter, err := NewReputationFilter(&kitconfig.ReputationFilterConfig{
				Enabled:      true,
				Mode:         kitconfig.ReputationModeEnforce,
				MinPageRank:  0.10,
				MinTrustRank: 0.20,
			}, reader)
			if err != nil {
				t.Fatalf("NewReputationFilter: %v", err)
			}

			result := matchReputation(t, filter, nostr.KindTextNote, fixturePubKey(7), nil)
			if result.Allowed != test.allowed {
				t.Fatalf("Allowed = %v, want %v (reason %q)", result.Allowed, test.allowed, result.Reason)
			}
			if !test.allowed {
				if !strings.HasPrefix(result.Reason, "restricted: ") {
					t.Fatalf("reason = %q, want a 'restricted: ' prefix", result.Reason)
				}
				if result.Reason != "restricted: The event author's reputation does not meet this relay's requirements." {
					t.Errorf("unexpected public reason: %q", result.Reason)
				}
			}
		})
	}
}

func TestReputationFilterPassDoesNotRecordObservation(t *testing.T) {
	reader := &fakeReputationReader{assessment: reputation.Assessment{
		Ready: true,
		Known: true,
		Score: reputation.Score{PageRank: 0.5, TrustRank: 0.5},
	}}
	filter, err := NewReputationFilter(&kitconfig.ReputationFilterConfig{
		Enabled: true,
		Mode:    kitconfig.ReputationModeObserve,
	}, reader)
	if err != nil {
		t.Fatalf("NewReputationFilter: %v", err)
	}

	meta := map[string]any{}
	result := matchReputation(t, filter, nostr.KindTextNote, fixturePubKey(8), meta)
	if !result.Allowed {
		t.Fatalf("passing author was rejected: %s", result.Reason)
	}
	if len(meta) != 0 {
		t.Fatalf("passing author produced observation metadata: %#v", meta)
	}
}

func TestReputationRejectionsUseHumanReadableMessages(t *testing.T) {
	for _, test := range []struct {
		name       string
		assessment reputation.Assessment
		want       string
	}{
		{"unknown", reputation.Assessment{Ready: true}, "restricted: The event author is not in this relay's trusted network."},
		{"low pagerank", reputation.Assessment{Ready: true, Known: true, Score: reputation.Score{PageRank: 1e-7, TrustRank: 0.2}}, "restricted: The event author's reputation does not meet this relay's requirements."},
		{"low trustrank", reputation.Assessment{Ready: true, Known: true, Score: reputation.Score{PageRank: 0.1, TrustRank: 4.394921967211787e-7}}, "restricted: The event author's reputation does not meet this relay's requirements."},
		{"both low", reputation.Assessment{Ready: true, Known: true}, "restricted: The event author's reputation does not meet this relay's requirements."},
		{"invalid score", reputation.Assessment{Ready: true, Known: true, Score: reputation.Score{PageRank: math.NaN(), TrustRank: 0.2}}, "restricted: The event author's reputation does not meet this relay's requirements."},
	} {
		t.Run(test.name, func(t *testing.T) {
			filter, err := NewReputationFilter(&kitconfig.ReputationFilterConfig{
				Enabled: true, Mode: "enforce", MinPageRank: 0.1, MinTrustRank: 0.2,
			}, &fakeReputationReader{assessment: test.assessment})
			if err != nil {
				t.Fatal(err)
			}
			result := matchReputation(t, filter, nostr.KindTextNote, fixturePubKey(1), nil)
			if result.Allowed || result.Reason != test.want {
				t.Fatalf("user-facing result = %+v, want rejection with %q", result, test.want)
			}
		})
	}
}

func TestReputationFilterNilMetaDoesNotPanic(t *testing.T) {
	reader := &fakeReputationReader{assessment: reputation.Assessment{Ready: true, Known: false}}
	filter, err := NewReputationFilter(&kitconfig.ReputationFilterConfig{
		Enabled: true,
		Mode:    kitconfig.ReputationModeObserve,
	}, reader)
	if err != nil {
		t.Fatalf("NewReputationFilter: %v", err)
	}

	result := matchReputation(t, filter, nostr.KindTextNote, fixturePubKey(9), nil)
	if !result.Allowed {
		t.Fatalf("observe mode rejected with nil metadata: %s", result.Reason)
	}
}
