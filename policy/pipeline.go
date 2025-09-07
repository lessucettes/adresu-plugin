// policy/pipeline.go
package policy

import (
	"adresu-plugin/config"
	"context"
	"log/slog"
	"runtime/debug"

	"github.com/nbd-wtf/go-nostr"
)

type Pipeline struct {
	filters         []Filter
	autoBanFilter   *AutoBanFilter
	rejectionLevels map[string]config.LogLevel
}

func NewPipeline(cfg *config.Config, filters ...Filter) *Pipeline {
	var abf *AutoBanFilter

	for _, f := range filters {
		if v, ok := f.(*AutoBanFilter); ok {
			abf = v
			break
		}
	}

	return &Pipeline{
		filters:         filters,
		autoBanFilter:   abf,
		rejectionLevels: cfg.Log.RejectionLevels,
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
				"pubkey", event.PubKey,
				"stack", string(debug.Stack()),
			)
			result = Reject("internal: an unexpected error occurred in a filter")
		}
	}()

	for _, filter := range p.filters {
		result = filter.Check(ctx, event, remoteIP)
		if result.Action != ActionAccept {
			// Standardized log attributes.
			logAttrs := []slog.Attr{
				slog.String("filter_name", filter.Name()),
				slog.String("remote_ip", remoteIP),
				slog.String("event_id", event.ID),
				slog.Int("kind", event.Kind),
				slog.String("pubkey", event.PubKey),
				slog.String("reason", result.Message),
			}

			if len(result.SpecificAttrs) > 0 {
				group := slog.Attr{
					Key:   "details",
					Value: slog.GroupValue(result.SpecificAttrs...),
				}
				logAttrs = append(logAttrs, group)
			}

			if dryRun {
				slog.LogAttrs(ctx, slog.LevelInfo, "Dry-run: Event would be rejected", logAttrs...)
				return Accept()
			}

			if p.autoBanFilter != nil {
				p.autoBanFilter.HandleRejection(ctx, event, filter.Name())
			}

			logLevel := slog.LevelWarn // Default to Warn
			if level, ok := p.rejectionLevels[filter.Name()]; ok {
				logLevel = level.ToSlogLevel() // Use configured level if present.
			}

			slog.LogAttrs(ctx, logLevel, "Event rejected by filter", logAttrs...)

			return result
		}
	}

	slog.Debug("Event accepted by all filters", "event_id", event.ID, "pubkey", event.PubKey)
	return Accept()
}

// Filters returns the list of filters in the pipeline.
func (p *Pipeline) Filters() []Filter {
	return p.filters
}
