package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"

	"fiatjaf.com/nostr"
	"github.com/lessucettes/adresu-plugin/internal/config"
	kitconfig "github.com/lessucettes/adresu-plugin/pkg/adresu-kit/config"
	kitpolicy "github.com/lessucettes/adresu-plugin/pkg/adresu-kit/policy"
	kitrep "github.com/lessucettes/adresu-plugin/pkg/adresu-kit/reputation"
)

type messageReputationReader struct{ assessment kitrep.Assessment }

func (r messageReputationReader) Lookup(nostr.PubKey) kitrep.Assessment { return r.assessment }

func TestReputationMessagesSeparateClientTextFromDiagnostics(t *testing.T) {
	for _, known := range []bool{false, true} {
		for _, mode := range []string{"enforce", "observe", "dry-run"} {
			name := "unknown/" + mode
			if known {
				name = "known-low/" + mode
			}
			t.Run(name, func(t *testing.T) {
				var logs bytes.Buffer
				previous := slog.Default()
				slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
				t.Cleanup(func() { slog.SetDefault(previous) })
				assessment := kitrep.Assessment{Ready: true, Known: known}
				if known {
					assessment.Score = kitrep.Score{TrustRank: 4.394921967211787e-7}
				}
				cfg := &kitconfig.ReputationFilterConfig{Enabled: true, Mode: "enforce", MinTrustRank: 1e-6}
				if mode == "observe" {
					cfg.Mode = mode
				}
				filter, err := kitpolicy.NewReputationFilter(cfg, messageReputationReader{assessment})
				if err != nil {
					t.Fatal(err)
				}
				pipeline := NewPipeline(&config.Config{}, []kitpolicy.Filter{filter}, nil)
				t.Cleanup(func() { _ = pipeline.Close() })
				response, err := pipeline.ProcessEvent(context.Background(), &nostr.Event{Kind: 1}, "192.0.2.17", mode == "dry-run")
				if err != nil {
					t.Fatal(err)
				}
				if mode == "enforce" {
					want := "restricted: The event author is not in this relay's trusted network."
					if known {
						want = "restricted: The event author's reputation does not meet this relay's requirements."
					}
					if response.Action != "reject" || response.Msg != want {
						t.Fatalf("unexpected client response: %+v", response)
					}
				} else if response.Action != "accept" || response.Msg != "" {
					t.Fatalf("observation or dry-run leaked rejection text: %+v", response)
				}
				decoder := json.NewDecoder(&logs)
				count := 0
				for {
					var record map[string]any
					if err := decoder.Decode(&record); err == io.EOF {
						break
					} else if err != nil {
						t.Fatal(err)
					}
					count++
					for key, want := range map[string]any{
						"known": known, "trustrank": assessment.Score.TrustRank,
						"min_trustrank": cfg.MinTrustRank,
					} {
						if record[key] != want {
							t.Errorf("log %s = %v, want %v", key, record[key], want)
						}
					}
					for _, removed := range []string{"pagerank", "min_pagerank"} {
						if _, exists := record[removed]; exists {
							t.Errorf("log contains removed field %q", removed)
						}
					}
					if record["remote_ip"] != nil {
						t.Fatal("reputation diagnostic gained IP attribution")
					}
				}
				wantCount := 1
				if mode == "dry-run" {
					wantCount = 2
				}
				if count != wantCount {
					t.Fatalf("diagnostic records = %d, want %d", count, wantCount)
				}
			})
		}
	}
}

func TestReputationLogsNeverFeedIPBans(t *testing.T) {
	for _, mode := range []string{"observe", "enforce", "other-filter"} {
		t.Run(mode, func(t *testing.T) {
			var logs bytes.Buffer
			previous := slog.Default()
			slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
			t.Cleanup(func() { slog.SetDefault(previous) })
			var filter kitpolicy.Filter
			if mode == "other-filter" {
				filter = &recordingFilter{match: func(*nostr.Event) (kitpolicy.FilterResult, error) {
					return kitpolicy.FilterResult{Allowed: false, Filter: "OtherFilter", Reason: "content policy"}, nil
				}}
			} else {
				var err error
				filter, err = kitpolicy.NewReputationFilter(&kitconfig.ReputationFilterConfig{Enabled: true, Mode: mode}, unknownReputation{})
				if err != nil {
					t.Fatal(err)
				}
			}
			pipeline := NewPipeline(&config.Config{}, []kitpolicy.Filter{filter}, nil)
			t.Cleanup(func() { _ = pipeline.Close() })
			response, err := pipeline.ProcessEvent(context.Background(), &nostr.Event{Kind: 1}, "192.0.2.17", false)
			wantAction := "reject"
			wantMessage := "Event rejected by reputation policy"
			if mode == "observe" {
				wantAction, wantMessage = "accept", "Reputation observation"
			} else if mode == "other-filter" {
				wantMessage = "Event rejected by filter"
			}
			if err != nil || response.Action != wantAction {
				t.Fatalf("unexpected policy response: %+v, %v", response, err)
			}
			var record map[string]any
			if err := json.Unmarshal(bytes.TrimSpace(logs.Bytes()), &record); err != nil {
				t.Fatalf("invalid diagnostic log: %v: %s", err, logs.String())
			}
			if record["msg"] != wantMessage {
				t.Errorf("log message = %v, want %q", record["msg"], wantMessage)
			}
			if mode == "other-filter" {
				if record["remote_ip"] != "192.0.2.17" {
					t.Fatal("ordinary abuse rejection lost its IP attribution")
				}
			} else if strings.Contains(logs.String(), "192.0.2.17") || record["remote_ip"] != nil {
				t.Fatal("social reputation diagnostic can feed an IP ban")
			}
		})
	}
}

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
	pipeline := NewPipeline(&config.Config{}, []kitpolicy.Filter{reputation, next}, nil)
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
	if _, exists := next.lastMeta()[kitpolicy.ReputationDiagnosticKey]; exists {
		t.Fatal("diagnostic metadata was not consumed")
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
	pipeline := NewPipeline(&config.Config{}, []kitpolicy.Filter{reputation}, []RejectionHandler{autoban})
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
