package policy

import (
	"context"

	"github.com/nbd-wtf/go-nostr"
)

type PolicyResponse struct {
	ID     string `json:"id"`
	Action string `json:"action"`
	Msg    string `json:"msg,omitempty"`
}

type Filter interface {
	Match(ctx context.Context, ev *nostr.Event, meta map[string]any) (pass bool, reason error)
}
