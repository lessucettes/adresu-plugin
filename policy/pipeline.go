// policy/pipeline.go
package policy

import (
	"context"
	"log/slog"
	"runtime/debug"

	"github.com/nbd-wtf/go-nostr"
)

type Pipeline struct {
	filters       []Filter
	autoBanFilter *AutoBanFilter
}

func NewPipeline(filters ...Filter) *Pipeline {
	var abf *AutoBanFilter

	for _, f := range filters {
		if v, ok := f.(*AutoBanFilter); ok {
			abf = v
			break
		}
	}

	return &Pipeline{
		filters:       filters,
		autoBanFilter: abf,
	}
}

// ProcessEvent runs an event through all filters in the pipeline.
// It stops and returns the result of the first filter that does not accept the event.
func (p *Pipeline) ProcessEvent(ctx context.Context, event *nostr.Event, remoteIP string, dryRun bool) (result *Result) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("Panic recovered in filter pipeline",
				"panic", r,
				"event_id", event.ID,
				"author", event.PubKey,
				"stack", string(debug.Stack()),
			)
			result = Reject("internal: an unexpected error occurred in a filter")
		}
	}()

	for _, filter := range p.filters {
		result = filter.Check(ctx, event, remoteIP)
		if result.Action != "accept" {
			if dryRun {
				slog.Info("Dry-run: Event would be rejected by filter",
					"filter", filter.Name(),
					"ip", remoteIP,
					"event_id", event.ID,
					"event_kind", event.Kind,
					"author", event.PubKey,
					"reason", result.Message,
				)
				return Accept()
			}
			if p.autoBanFilter != nil {
				p.autoBanFilter.HandleRejection(ctx, event, filter.Name())
			}
			logLevel := slog.LevelWarn
			if filter.Name() == "KindFilter" {
				logLevel = slog.LevelDebug
			}
			slog.Log(ctx, logLevel,
				"Event rejected by filter",
				"filter", filter.Name(),
				"ip", remoteIP,
				"event_id", event.ID,
				"event_kind", event.Kind,
				"author", event.PubKey,
				"reason", result.Message,
			)
			return result
		}
	}

	slog.Debug("Event accepted by all filters", "event_id", event.ID, "author", event.PubKey)
	return Accept()
}

// Filters returns the list of filters in the pipeline.
func (p *Pipeline) Filters() []Filter {
	return p.filters
}
