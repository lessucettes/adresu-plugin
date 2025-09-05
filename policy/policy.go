// policy/policy.go
package policy

import (
	"context"

	"github.com/nbd-wtf/go-nostr"
)

const (
	ActionAccept = "accept"
	ActionReject = "reject"
)

// Result defines the outcome of a filter check.
type Result struct {
	Action  string
	Message string
}

func Accept() *Result {
	return &Result{Action: ActionAccept}
}

func Reject(msg string) *Result {
	return &Result{Action: ActionReject, Message: msg}
}

type Filter interface {
	Name() string
	Check(ctx context.Context, event *nostr.Event, remoteIP string) *Result
}
