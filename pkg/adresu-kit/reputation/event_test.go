package reputation

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"fiatjaf.com/nostr"
)

func signedFollowEvent(t *testing.T, tags nostr.Tags) nostr.Event {
	t.Helper()
	event := nostr.Event{Kind: 3, CreatedAt: nostr.Timestamp(time.Now().Unix()), Tags: tags}
	if err := event.Sign(nostr.KeyOne); err != nil {
		t.Fatal(err)
	}
	return event
}

func TestParseFollowList(t *testing.T) {
	other := nostr.Generate().Public()
	event := signedFollowEvent(t, nostr.Tags{{"p", other.Hex()}, {"p", other.Hex()}, {"p", nostr.KeyOne.Public().Hex()}, {"p", "broken"}})
	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	list, err := ParseFollowList(context.Background(), raw, 10, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if list.Author != event.PubKey || list.EventID != event.ID || len(list.Follows) != 1 || list.Follows[0] != other {
		t.Fatalf("unexpected list: %+v", list)
	}
	if list.FetchedAt.IsZero() {
		t.Fatal("missing receipt time")
	}
}

func TestParseFollowListEmptyAndInvalid(t *testing.T) {
	for _, name := range []string{"empty", "id", "signature", "kind", "future", "bounds", "cancelled"} {
		t.Run(name, func(t *testing.T) {
			event := signedFollowEvent(t, nil)
			ctx := context.Background()
			limit := 10
			switch name {
			case "id":
				event.ID[0] ^= 1
			case "signature":
				event.Sig[0] ^= 1
			case "kind":
				event.Kind = 1
			case "future":
				event.CreatedAt = nostr.Timestamp(time.Now().Add(time.Hour).Unix())
				if err := event.Sign(nostr.KeyOne); err != nil {
					t.Fatal(err)
				}
			case "bounds":
				limit = 0
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			raw, err := json.Marshal(event)
			if err != nil {
				t.Fatal(err)
			}
			list, err := ParseFollowList(ctx, raw, limit, time.Now())
			if name == "empty" {
				if err != nil || len(list.Follows) != 0 {
					t.Fatalf("signed empty list rejected: %v", err)
				}
			} else if err == nil {
				t.Fatal("invalid list accepted")
			}
		})
	}
}

func TestParseFollowListRejectsOversizedUniqueList(t *testing.T) {
	event := signedFollowEvent(t, nostr.Tags{{"p", nostr.Generate().Public().Hex()}, {"p", nostr.Generate().Public().Hex()}})
	raw, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseFollowList(context.Background(), raw, 1, time.Now()); err == nil {
		t.Fatal("oversized list accepted")
	}
}
