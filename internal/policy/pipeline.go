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
	kitrep "github.com/lessucettes/adresu-plugin/pkg/adresu-kit/reputation"
)

// errPipelineClosed is returned for events that arrive after Close started.
var errPipelineClosed = errors.New("policy pipeline is closed")

type PolicyResponse struct {
	ID     string `json:"id"`
	Action string `json:"action"`
	Msg    string `json:"msg,omitempty"`
}

type RejectionHandler interface {
	HandleRejection(ctx context.Context, ev *nostr.Event, filterName string)
}

type Pipeline struct {
	filters           []kitpolicy.Filter
	rejectionHandlers []RejectionHandler
	rejectionLevels   map[string]config.LogLevel

	// mu keeps Close from closing filters under a running ProcessEvent and
	// stops WaitGroup misuse when events arrive during shutdown.
	mu        sync.RWMutex
	closed    bool
	closeDone chan struct{}
}

func NewPipeline(
	cfg *config.Config,
	filters []kitpolicy.Filter,
	handlers []RejectionHandler,
) *Pipeline {
	return &Pipeline{
		filters:           filters,
		rejectionHandlers: handlers,
		rejectionLevels:   cfg.Log.RejectionLevels,
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

	for _, filter := range p.filters {
		res, filterErr := filter.Match(ctx, event, meta)
		if filterErr != nil {
			slog.Error("Filter execution failed", "error", filterErr, "filter_name", res.Filter, "event_id", eventID)
			return PolicyResponse{ID: eventID, Action: "reject", Msg: "An internal error occurred while running filter " + res.Filter + "."}, filterErr
		}
		logReputationObservation(event, meta)

		if !res.Allowed {
			message := "Event rejected by filter"
			logAttrs := []slog.Attr{slog.String("filter_name", res.Filter)}
			if res.Filter == kitpolicy.ReputationFilterName {
				// Forwarding an unknown author's event is not IP abuse. Keep
				// social-policy diagnostics out of the Fail2Ban input stream.
				message = "Event rejected by reputation policy"
				logAttrs = append(logAttrs, reputationDiagnosticAttrs(meta)...)
			} else {
				logAttrs = append(logAttrs, slog.String("remote_ip", remoteIP))
			}
			logAttrs = append(logAttrs,
				slog.String("event_id", eventID),
				slog.Int("kind", int(event.Kind)),
				slog.String("pubkey", event.PubKey.Hex()),
				slog.String("reason", res.Reason),
			)
			logLevel := slog.LevelWarn
			if level, ok := p.rejectionLevels[res.Filter]; ok {
				logLevel = level.ToSlogLevel()
			}
			slog.LogAttrs(ctx, logLevel, message, logAttrs...)

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

	for _, filter := range p.filters {
		if closer, ok := filter.(interface{ Close() error }); ok {
			if err := closer.Close(); err != nil {
				slog.Error("Failed to close a filter component", "filter", filter, "error", err)
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

func logReputationObservation(event *nostr.Event, meta map[string]any) {
	assessment, ok := meta[kitpolicy.ReputationObservationKey].(kitrep.Assessment)
	if !ok {
		return
	}
	delete(meta, kitpolicy.ReputationObservationKey)
	// This is deliberately not an "Event rejected by filter" log record and has
	// no remote IP: observation must not feed the production Fail2Ban jails.
	details := reputationDiagnosticAttrs(meta)
	if len(details) == 0 {
		// Preserve observation metadata compatibility for standalone producers.
		details = []slog.Attr{
			slog.Bool("known", assessment.Known), slog.Float64("pagerank", assessment.Score.PageRank),
			slog.Float64("trustrank", assessment.Score.TrustRank),
		}
	}
	attrs := []slog.Attr{
		slog.Bool("would_reject", true), slog.String("event_id", event.ID.Hex()),
		slog.String("pubkey", event.PubKey.Hex()), slog.Int("kind", int(event.Kind)),
	}
	slog.LogAttrs(nil, slog.LevelInfo, "Reputation observation", append(attrs, details...)...)
}

func reputationDiagnosticAttrs(meta map[string]any) []slog.Attr {
	diagnostic, ok := meta[kitpolicy.ReputationDiagnosticKey].(kitpolicy.ReputationDiagnostic)
	if !ok {
		return nil
	}
	delete(meta, kitpolicy.ReputationDiagnosticKey)
	return []slog.Attr{
		slog.Bool("known", diagnostic.Assessment.Known),
		slog.Float64("pagerank", diagnostic.Assessment.Score.PageRank),
		slog.Float64("trustrank", diagnostic.Assessment.Score.TrustRank),
		slog.Float64("min_pagerank", diagnostic.MinPageRank),
		slog.Float64("min_trustrank", diagnostic.MinTrustRank),
	}
}
