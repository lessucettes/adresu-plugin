package policy

import (
	"context"
	"log/slog"
	"runtime/debug"

	"github.com/lessucettes/adresu-plugin/config"
	"github.com/nbd-wtf/go-nostr"
)

type PipelineStage struct {
	Name   string
	Filter Filter
}

type Pipeline struct {
	stages          []PipelineStage
	autoBanFilter   *AutoBanFilter
	rejectionLevels map[string]config.LogLevel
}

func NewPipeline(cfg *config.Config, stages []PipelineStage, abf *AutoBanFilter) *Pipeline {
	return &Pipeline{
		stages:          stages,
		autoBanFilter:   abf,
		rejectionLevels: cfg.Log.RejectionLevels,
	}
}

func (p *Pipeline) ProcessEvent(ctx context.Context, event *nostr.Event, remoteIP string, dryRun bool) (response PolicyResponse) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("Panic recovered in filter pipeline",
				"panic", r, "event_id", event.ID, "pubkey", event.PubKey, "stack", string(debug.Stack()),
			)
			response = PolicyResponse{ID: event.ID, Action: "reject", Msg: "internal: an unexpected error occurred"}
		}
	}()

	meta := map[string]any{
		"remote_ip": remoteIP,
	}

	for _, stage := range p.stages {
		pass, reason := stage.Filter.Match(ctx, event, meta)
		if !pass {
			rejectionMsg := "blocked by " + stage.Name
			if reason != nil {
				rejectionMsg = reason.Error()
			}

			logAttrs := []slog.Attr{
				slog.String("filter_name", stage.Name),
				slog.String("remote_ip", remoteIP),
				slog.String("event_id", event.ID),
				slog.Int("kind", event.Kind),
				slog.String("pubkey", event.PubKey),
				slog.String("reason", rejectionMsg),
			}
			logLevel := slog.LevelWarn
			if level, ok := p.rejectionLevels[stage.Name]; ok {
				logLevel = level.ToSlogLevel()
			}
			slog.LogAttrs(ctx, logLevel, "Event rejected by filter", logAttrs...)

			if dryRun {
				slog.LogAttrs(ctx, slog.LevelInfo, "Dry-run: Event would be rejected", logAttrs...)
				return PolicyResponse{ID: event.ID, Action: "accept"}
			}

			if p.autoBanFilter != nil {
				p.autoBanFilter.HandleRejection(ctx, event, stage.Name)
			}

			return PolicyResponse{ID: event.ID, Action: "reject", Msg: rejectionMsg}
		}
	}

	slog.Debug("Event accepted by all filters", "event_id", event.ID, "pubkey", event.PubKey)
	return PolicyResponse{ID: event.ID, Action: "accept"}
}
