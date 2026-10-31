package policy

import (
	"context"
	"testing"
	"time"

	"fiatjaf.com/nostr"
)

// The constructor explicitly accepts a nil config; Match must not dereference it.
func TestFreshnessFilterNilConfigAllows(t *testing.T) {
	filter, err := NewFreshnessFilter(nil)
	if err != nil {
		t.Fatal(err)
	}

	res, err := filter.Match(context.Background(), &nostr.Event{Kind: nostr.KindTextNote, CreatedAt: nostr.Now()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Allowed {
		t.Fatalf("event rejected without freshness limits: %s", res.Reason)
	}

	old, err := filter.Match(context.Background(), &nostr.Event{Kind: nostr.KindTextNote, CreatedAt: nostr.Timestamp(time.Now().Add(-time.Hour).Unix())}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !old.Allowed {
		t.Fatalf("old event rejected without freshness limits: %s", old.Reason)
	}
}
