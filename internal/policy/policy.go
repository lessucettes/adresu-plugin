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

type RejectionHandler interface {
	HandleRejection(ctx context.Context, ev *nostr.Event, filterName string)
}
