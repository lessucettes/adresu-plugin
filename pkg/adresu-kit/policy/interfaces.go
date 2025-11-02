package policy

import (
	"context"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

// FilterResult is the structured return type for all filters.
type FilterResult struct {
	Allowed  bool
	Filter   string
	Reason   string
	Duration time.Duration
}

// Filter is the interface that all kit filters must implement.
type Filter interface {
	Match(ctx context.Context, ev *nostr.Event, meta map[string]any) (FilterResult, error)
}

// NewResultFunc returns a helper function for creating FilterResult objects.
func NewResultFunc(filterName string) func(allowed bool, reason string, err error) (FilterResult, error) {
	start := time.Now()
	return func(allowed bool, reason string, err error) (FilterResult, error) {
		return FilterResult{
			Allowed:  allowed,
			Filter:   filterName,
			Reason:   reason,
			Duration: time.Since(start),
		}, err
	}
}
