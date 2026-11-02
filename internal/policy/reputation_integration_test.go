package policy

import (
	"context"
	"testing"

	"fiatjaf.com/nostr"
	"github.com/lessucettes/adresu-plugin/internal/config"
	kitconfig "github.com/lessucettes/adresu-plugin/pkg/adresu-kit/config"
	kitpolicy "github.com/lessucettes/adresu-plugin/pkg/adresu-kit/policy"
	kitrep "github.com/lessucettes/adresu-plugin/pkg/adresu-kit/reputation"
)

type unknownReputation struct{}

func (unknownReputation) Lookup(nostr.PubKey) kitrep.Assessment {
	return kitrep.Assessment{Ready: true}
}

func TestReputationObservationStillRunsRemainingFilters(t *testing.T) {
	reputation, err := kitpolicy.NewReputationFilter(&kitconfig.ReputationFilterConfig{Enabled: true, Mode: "observe"}, unknownReputation{})
	if err != nil {
		t.Fatal(err)
	}
	next := &recordingFilter{match: func(*nostr.Event) (kitpolicy.FilterResult, error) {
		return kitpolicy.FilterResult{Allowed: false, Filter: "NextFilter", Reason: "other policy"}, nil
	}}
	pipeline := NewPipeline(&config.Config{}, []PipelineStage{{Filter: reputation}, {Filter: next}}, nil, nil)
	defer pipeline.Close()
	event := &nostr.Event{Kind: 1, PubKey: nostr.KeyOne.Public()}
	response, err := pipeline.ProcessEvent(context.Background(), event, "", false)
	if err != nil || response.Action != "reject" || response.Msg != "other policy" {
		t.Fatalf("observation bypassed another filter: %+v %v", response, err)
	}
	if len(next.metas) != 1 {
		t.Fatal("later filter did not execute")
	}
	if _, exists := next.lastMeta()["reputation_observation"]; exists {
		t.Fatal("observation metadata was not consumed")
	}
}

func TestReputationRejectionsNeverBanAuthors(t *testing.T) {
	s := newTestStore()
	autoban, err := NewAutoBanFilter(s, newAutoBanConfig(1))
	if err != nil {
		t.Fatal(err)
	}
	reputation, err := kitpolicy.NewReputationFilter(&kitconfig.ReputationFilterConfig{Enabled: true, Mode: "enforce"}, unknownReputation{})
	if err != nil {
		t.Fatal(err)
	}
	pipeline := NewPipeline(&config.Config{}, []PipelineStage{{Filter: reputation}}, []RejectionHandler{autoban}, nil)
	key, _ := newKeyPair(t)
	event := signedEvent(t, key, nostr.KindTextNote, "new author", nil)
	response, err := pipeline.ProcessEvent(context.Background(), event, "", false)
	if err != nil || response.Action != "reject" {
		t.Fatalf("unknown author unexpectedly accepted: %+v %v", response, err)
	}
	if err := pipeline.Close(); err != nil {
		t.Fatal(err)
	}
	if s.banCount() != 0 {
		t.Fatal("lack of reputation caused an author ban")
	}
}
