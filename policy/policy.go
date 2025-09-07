// policy/policy.go
package policy

import (
	"context"
	"log/slog"

	"github.com/nbd-wtf/go-nostr"
)

const (
	ActionAccept = "accept"
	ActionReject = "reject"
)

// Result defines the outcome of a filter check.
type Result struct {
	Action        string
	Message       string
	SpecificAttrs []slog.Attr
}

func Accept() *Result {
	return &Result{Action: ActionAccept}
}

// Reject accepts optional slog.Attr for detailed logging.
func Reject(msg string, attrs ...slog.Attr) *Result {
	return &Result{Action: ActionReject, Message: msg, SpecificAttrs: attrs}
}

type Filter interface {
	Name() string
	Check(ctx context.Context, event *nostr.Event, remoteIP string) *Result
}
