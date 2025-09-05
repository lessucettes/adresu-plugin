// policy/tags_filter_test.go
package policy

import (
	"context"
	"testing"
	"time"

	"adresu-plugin/config"
	"adresu-plugin/testutils"

	"github.com/nbd-wtf/go-nostr"
	"github.com/stretchr/testify/require"
)

// ptr is a small helper to get a pointer to an int for the config.
func ptr(i int) *int { return &i }

func TestTagsFilter(t *testing.T) {
	ctx := context.Background()

	// A comprehensive config that tests all rule types.
	cfg := &config.TagsFilterConfig{
		Rules: []config.TagRule{
			{
				Description: "Notes (kind 1) can have at most 2 tags total.",
				Kinds:       []int{1},
				MaxTags:     ptr(2),
			},
			{
				Description:  "Follow lists (kind 3) can have at most 1 'p' tag.",
				Kinds:        []int{3},
				MaxTagCounts: map[string]int{"p": 1},
			},
			{
				Description:  "Long-form posts (kind 30023) must have a 'd' tag.",
				Kinds:        []int{30023},
				RequiredTags: []string{"d"},
			},
		},
	}
	filter := NewTagsFilter(cfg)

	now := time.Now()

	testCases := []struct {
		name           string
		event          *nostr.Event
		expectedAction string
	}{
		// --- MaxTags Rule Tests ---
		{
			name: "MaxTags: accept when tag count is at the limit",
			event: testutils.MakeEvent(
				1, "", testutils.TestPubKey, now,
				nostr.Tag{"e", "id"},
				nostr.Tag{"p", "pk"},
			),
			expectedAction: ActionAccept,
		},
		{
			name: "MaxTags: reject when tag count is over the limit",
			event: testutils.MakeEvent(
				1, "", testutils.TestPubKey, now,
				nostr.Tag{"e", "id"},
				nostr.Tag{"p", "pk"},
				nostr.Tag{"t", "tag"},
			),
			expectedAction: ActionReject,
		},

		// --- MaxTagCounts Rule Tests ---
		{
			name: "MaxTagCounts: accept when specific tag count is at the limit",
			event: testutils.MakeEvent(
				3, "", testutils.TestPubKey, now,
				nostr.Tag{"p", "pk1"},
				nostr.Tag{"t", "tag"},
			),
			expectedAction: ActionAccept,
		},
		{
			name: "MaxTagCounts: reject when specific tag count is over the limit",
			event: testutils.MakeEvent(
				3, "", testutils.TestPubKey, now,
				nostr.Tag{"p", "pk1"},
				nostr.Tag{"p", "pk2"},
			),
			expectedAction: ActionReject,
		},

		// --- RequiredTags Rule Tests ---
		{
			name: "RequiredTags: accept when required tag is present",
			event: testutils.MakeEvent(
				30023, "", testutils.TestPubKey, now,
				nostr.Tag{"d", "identifier"},
			),
			expectedAction: ActionAccept,
		},
		{
			name: "RequiredTags: reject when required tag is missing",
			event: testutils.MakeEvent(
				30023, "", testutils.TestPubKey, now,
				nostr.Tag{"title", "My Post"},
			),
			expectedAction: ActionReject,
		},

		// --- General Behavior Tests ---
		{
			name: "Accept event for a kind with no rules",
			event: testutils.MakeEvent(
				7, "", testutils.TestPubKey, now,
				nostr.Tag{"e", "id"},
				nostr.Tag{"p", "pk"},
			),
			expectedAction: ActionAccept,
		},
		{
			name:           "Accept event with no tags when no rules apply",
			event:          testutils.MakeEvent(42, "", testutils.TestPubKey, now /* no tags */),
			expectedAction: ActionAccept,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := filter.Check(ctx, tc.event, "127.0.0.1")
			require.Equal(t, tc.expectedAction, result.Action)
		})
	}
}
