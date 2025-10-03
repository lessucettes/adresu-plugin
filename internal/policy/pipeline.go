package policy

import (
	"context"
	"log/slog"
	"runtime/debug"
	"sync"

	kitpolicy "github.com/lessucettes/adresu-kit/policy"
	"github.com/nbd-wtf/go-nostr"

	"github.com/lessucettes/adresu-plugin/internal/config"
)

type MetricsCollector interface {
	Report(res kitpolicy.FilterResult)
}

type PipelineStage struct {
	Filter kitpolicy.Filter
}

type Pipeline struct {
	stages            []PipelineStage
	rejectionHandlers []RejectionHandler
	rejectionLevels   map[string]config.LogLevel
	collector         MetricsCollector
	wg                sync.WaitGroup
}

func NewPipeline(
	cfg *config.Config,
	stages []PipelineStage,
	handlers []RejectionHandler,
	collector MetricsCollector,
) *Pipeline {
	return &Pipeline{
		stages:            stages,
		rejectionHandlers: handlers,
		rejectionLevels:   cfg.Log.RejectionLevels,
		collector:         collector,
	}
}

func (p *Pipeline) ProcessEvent(
	ctx context.Context,
	event *nostr.Event,
	remoteIP string,
	dryRun bool,
) (response PolicyResponse, err error) {
	p.wg.Add(1)
	defer p.wg.Done()

	defer func() {
		if r := recover(); r != nil {
			slog.Error("Panic recovered in filter pipeline",
				"panic", r, "event_id", event.ID, "pubkey", event.PubKey, "stack", string(debug.Stack()),
			)
			response = PolicyResponse{ID: event.ID, Action: "reject", Msg: "internal: an unexpected error occurred"}
			err = nil
		}
	}()

	meta := map[string]any{
		"remote_ip": remoteIP,
	}

	for _, stage := range p.stages {
		res, filterErr := stage.Filter.Match(ctx, event, meta)
		if filterErr != nil {
			slog.Error("Filter execution failed", "error", filterErr, "filter_name", res.Filter, "event_id", event.ID)
			return PolicyResponse{ID: event.ID, Action: "reject", Msg: "internal: error in filter " + res.Filter}, filterErr
		}

		if p.collector != nil {
			p.collector.Report(res)
		}

		if !res.Allowed {
			logAttrs := []slog.Attr{
				slog.String("filter_name", res.Filter),
				slog.String("remote_ip", remoteIP),
				slog.String("event_id", event.ID),
				slog.Int("kind", event.Kind),
				slog.String("pubkey", event.PubKey),
				slog.String("reason", res.Reason),
			}
			logLevel := slog.LevelWarn
			if level, ok := p.rejectionLevels[res.Filter]; ok {
				logLevel = level.ToSlogLevel()
			}
			slog.LogAttrs(ctx, logLevel, "Event rejected by filter", logAttrs...)

			if dryRun {
				slog.LogAttrs(ctx, slog.LevelInfo, "Dry-run: Event would be rejected", logAttrs...)
				return PolicyResponse{ID: event.ID, Action: "accept"}, nil
			}

			for _, handler := range p.rejectionHandlers {
				handler.HandleRejection(ctx, event, res.Filter)
			}

			return PolicyResponse{ID: event.ID, Action: "reject", Msg: res.Reason}, nil
		}
	}

	slog.Debug("Event accepted by all filters", "event_id", event.ID, "pubkey", event.PubKey)
	return PolicyResponse{ID: event.ID, Action: "accept"}, nil
}

func (p *Pipeline) Close() error {
	p.wg.Wait()

	for _, stage := range p.stages {
		if closer, ok := stage.Filter.(interface{ Close() error }); ok {
			if err := closer.Close(); err != nil {
				slog.Error("Failed to close a filter component", "filter", stage.Filter, "error", err)
			}
		}
	}
	return nil
}
