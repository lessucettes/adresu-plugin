// Package policy provides composable, in-process Nostr event filters.
// Applications own filter ordering, event admission, persistence and responses;
// the filters do not depend on the strfry plugin or its internal packages.
package policy

import (
	"context"
	"time"

	"fiatjaf.com/nostr"
)

// FilterResult is the structured return type for all filters.
type FilterResult struct {
	Allowed  bool
	Filter   string
	Reason   string        // Human-readable explanation, also used in rejection logs and responses.
	Duration time.Duration // Elapsed time since this Match call created its result helper.
}

// Filter is the interface that all kit filters must implement. Callers supply
// a non-nil context and event, and validate event IDs and signatures at admission.
// Configuration must not be modified after construction.
//
// meta is optional, request-local state shared by filters in one evaluation.
// Rate and emergency filters read "remote_ip" (string); the language filter
// writes "language" (string). Reputation metadata uses the exported keys in
// reputation_filter.go. Do not share a mutable meta map between concurrent calls.
// A policy rejection has Allowed=false and a nil error; operational errors are
// returned separately and require an application-level error policy.
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
