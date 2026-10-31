package policy

import (
	"context"

	"fiatjaf.com/nostr"
)

type PolicyResponse struct {
	ID     string `json:"id"`
	Action string `json:"action"`
	Msg    string `json:"msg,omitempty"`
}

type RejectionHandler interface {
	HandleRejection(ctx context.Context, ev *nostr.Event, filterName string)
}
