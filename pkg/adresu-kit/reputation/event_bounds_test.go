package reputation

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"fiatjaf.com/nostr"
)

func TestFollowTagBudgetIncludesDuplicatesAndInvalidTargets(t *testing.T) {
	for _, target := range []string{nostr.Generate().Public().Hex(), strings.Repeat("f", 64), "invalid"} {
		event := signedFollowEvent(t, nostr.Tags{{"p", target}, {"p", target}})
		raw, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseFollowList(context.Background(), raw, 1, time.Now()); err == nil {
			t.Fatalf("repeated p tags bypassed the work budget: %q", target)
		}
	}
}

type parseCancelContext struct {
	context.Context
	checks int
}

func (c *parseCancelContext) Err() error {
	c.checks--
	if c.checks <= 0 {
		return context.Canceled
	}
	return nil
}

func TestFollowListParsingChecksCancellationDuringTagWork(t *testing.T) {
	tags := make(nostr.Tags, 256)
	for i := range tags {
		tags[i] = nostr.Tag{"p", nostr.KeyOne.Public().Hex()}
	}
	raw, err := json.Marshal(signedFollowEvent(t, tags))
	if err != nil {
		t.Fatal(err)
	}
	ctx := &parseCancelContext{Context: context.Background(), checks: 3}
	if _, err := ParseFollowList(ctx, raw, len(tags), time.Now()); !errors.Is(err, context.Canceled) {
		t.Fatalf("tag work ignored cancellation: %v", err)
	}
}
