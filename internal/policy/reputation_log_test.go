package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"fiatjaf.com/nostr"
	"github.com/lessucettes/adresu-plugin/internal/config"
	kitconfig "github.com/lessucettes/adresu-plugin/pkg/adresu-kit/config"
	kitpolicy "github.com/lessucettes/adresu-plugin/pkg/adresu-kit/policy"
)

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
			pipeline := NewPipeline(&config.Config{}, []PipelineStage{{Filter: filter}}, nil, nil)
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
