package policy

import (
	"context"
	"errors"
	"log/slog"
	"runtime/debug"
	"sync"

	"fiatjaf.com/nostr"
	kitpolicy "github.com/lessucettes/adresu-plugin/pkg/adresu-kit/policy"

	"github.com/lessucettes/adresu-plugin/internal/config"
)

// errPipelineClosed is returned for events that arrive after Close started.
var errPipelineClosed = errors.New("policy pipeline is closed")

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

	// mu keeps Close from closing filters under a running ProcessEvent and
	// stops WaitGroup misuse when events arrive during shutdown.
	mu        sync.RWMutex
	closed    bool
	closeDone chan struct{}
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
		closeDone:         make(chan struct{}),
	}
}

func (p *Pipeline) ProcessEvent(
	ctx context.Context,
	event *nostr.Event,
	remoteIP string,
	dryRun bool,
) (response PolicyResponse, err error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if event == nil {
		return PolicyResponse{Action: "reject", Msg: "Event is missing."}, nil
	}
	eventID := event.ID.Hex()
	if p.closed {
		return PolicyResponse{ID: eventID, Action: "reject", Msg: "The policy pipeline is shutting down."}, errPipelineClosed
	}

	defer func() {
		if r := recover(); r != nil {
			slog.Error("Panic recovered in filter pipeline",
				"panic", r, "event_id", eventID, "pubkey", event.PubKey.Hex(), "stack", string(debug.Stack()),
			)
			response = PolicyResponse{ID: eventID, Action: "reject", Msg: "An unexpected internal error occurred."}
			err = nil
		}
	}()

	meta := map[string]any{
		"remote_ip": remoteIP,
		"dry_run":   dryRun,
	}

	for _, stage := range p.stages {
		res, filterErr := stage.Filter.Match(ctx, event, meta)
		if filterErr != nil {
			slog.Error("Filter execution failed", "error", filterErr, "filter_name", res.Filter, "event_id", eventID)
			return PolicyResponse{ID: eventID, Action: "reject", Msg: "An internal error occurred while running filter " + res.Filter + "."}, filterErr
		}

		if p.collector != nil {
			p.collector.Report(res)
		}

		if !res.Allowed {
			logAttrs := []slog.Attr{
				slog.String("filter_name", res.Filter),
				slog.String("remote_ip", remoteIP),
				slog.String("event_id", eventID),
				slog.Int("kind", int(event.Kind)),
				slog.String("pubkey", event.PubKey.Hex()),
				slog.String("reason", res.Reason),
			}
			logLevel := slog.LevelWarn
			if level, ok := p.rejectionLevels[res.Filter]; ok {
				logLevel = level.ToSlogLevel()
			}
			slog.LogAttrs(ctx, logLevel, "Event rejected by filter", logAttrs...)

			if dryRun {
				slog.LogAttrs(ctx, slog.LevelInfo, "Dry-run: Event would be rejected", logAttrs...)
				return PolicyResponse{ID: eventID, Action: "accept"}, nil
			}

			for _, handler := range p.rejectionHandlers {
				handler.HandleRejection(ctx, event, res.Filter)
			}

			return PolicyResponse{ID: eventID, Action: "reject", Msg: res.Reason}, nil
		}
	}

	slog.Debug("Event accepted by all filters", "event_id", eventID, "pubkey", event.PubKey.Hex())
	return PolicyResponse{ID: eventID, Action: "accept"}, nil
}

func (p *Pipeline) Close() error {
	p.mu.Lock()
	if p.closed {
		done := p.closeDone
		p.mu.Unlock()
		if done != nil {
			<-done
		}
		return nil
	}
	p.closed = true
	if p.closeDone == nil {
		p.closeDone = make(chan struct{})
	}
	done := p.closeDone
	p.mu.Unlock()

	for _, stage := range p.stages {
		if closer, ok := stage.Filter.(interface{ Close() error }); ok {
			if err := closer.Close(); err != nil {
				slog.Error("Failed to close a filter component", "filter", stage.Filter, "error", err)
			}
		}
	}
	for _, handler := range p.rejectionHandlers {
		if closer, ok := handler.(interface{ Close() error }); ok {
			if err := closer.Close(); err != nil {
				slog.Error("Failed to close a rejection handler", "handler", handler, "error", err)
			}
		}
	}

	close(done)
	return nil
}
