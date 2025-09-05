// policy/moderation_filter_test.go
package policy

import (
	"adresu-plugin/testutils"
	"context"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/stretchr/testify/require"
)

func TestModerationFilter(t *testing.T) {
	ctx := context.Background()

	// Use realistic 64-char hex keys.
	const moderator = "61d82471a1c354588505f76159c7871c5107600bc85acf8974490b73785c7cfc"
	const userA = "4b065861e8668125e2d489cb791b4e907bd83a87f2a8988425d31fb89516c109"
	const banEmoji = "🔨"
	const unbanEmoji = "🔓"

	// Helper: build a moderator reaction with optional "p" tag target.
	makeModEvent := func(author, content, target string) *nostr.Event {
		ev := &nostr.Event{
			Kind:      nostr.KindReaction,
			PubKey:    author,
			Content:   content,
			CreatedAt: nostr.Now(),
		}
		if target != "" {
			ev.Tags = nostr.Tags{{"p", target}}
		}
		return ev
	}

	tests := []struct {
		name               string
		event              *nostr.Event
		initialBans        map[string]bool
		expectBan          bool
		expectUnban        bool
		expectDeleteEvents bool
	}{
		{
			name:               "Moderator bans a user",
			event:              makeModEvent(moderator, banEmoji, userA),
			expectBan:          true,
			expectDeleteEvents: true,
		},
		{
			name:        "Moderator unbans a user",
			event:       makeModEvent(moderator, unbanEmoji, userA),
			initialBans: map[string]bool{userA: true},
			expectUnban: true,
		},
		{
			name:  "Non-moderator tries to ban",
			event: makeModEvent(userA, banEmoji, "someone_else"),
		},
		{
			name:  "Moderator sends non-reaction event",
			event: &nostr.Event{Kind: nostr.KindTextNote, PubKey: moderator, Content: banEmoji},
		},
		{
			name:  "Moderator reaction has no 'p' tag",
			event: makeModEvent(moderator, banEmoji, ""),
		},
		{
			name:  "Moderator tries to ban themself",
			event: makeModEvent(moderator, banEmoji, moderator),
		},
		{
			name:  "Moderator uses unrelated emoji",
			event: makeModEvent(moderator, "👍", userA),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := testutils.NewMockStore()
			// Seed initial ban state via the store API.
			if tc.initialBans != nil {
				for k, banned := range tc.initialBans {
					if banned {
						_ = s.BanAuthor(ctx, k, time.Hour)
					}
				}
			}

			cli := testutils.NewMockStrfryClient(1)
			filter := NewModerationFilter(moderator, banEmoji, unbanEmoji, s, cli, time.Hour)

			res := filter.Check(ctx, tc.event, "127.0.0.1")
			require.Equal(t, ActionAccept, res.Action, "Moderation events themselves should be accepted")

			// Asynchronous delete expectation.
			if tc.expectDeleteEvents {
				select {
				case deleted := <-cli.DeleteSignal:
					require.Equal(t, userA, deleted, "DeleteEventsByAuthor should be called for the target user")
				case <-time.After(300 * time.Millisecond):
					t.Fatal("timed out waiting for strfry delete signal")
				}
			}

			// Ban / unban expectations.
			if tc.expectBan {
				isBanned, _ := s.IsAuthorBanned(ctx, userA)
				require.True(t, isBanned, "User should be banned in the store")
			}
			if tc.expectUnban {
				isBanned, _ := s.IsAuthorBanned(ctx, userA)
				require.False(t, isBanned, "User should be unbanned in the store")
			}

			// For purely negative cases, ensure no unintended side effects.
			if !tc.expectBan && !tc.expectUnban && !tc.expectDeleteEvents {
				want := false
				if tc.initialBans != nil {
					want = tc.initialBans[userA]
				}
				got, _ := s.IsAuthorBanned(ctx, userA)
				require.Equal(t, want, got, "Ban state should remain unchanged")
				require.Empty(t, cli.DeletedAuthors, "DeleteEventsByAuthor should not be called")
			}
		})
	}

	t.Run("Filter is disabled when moderator key is empty", func(t *testing.T) {
		s := testutils.NewMockStore()
		cli := testutils.NewMockStrfryClient(1)

		filter := NewModerationFilter("", banEmoji, unbanEmoji, s, cli, time.Hour) // disabled

		ev := makeModEvent(moderator, banEmoji, userA)
		_ = filter.Check(ctx, ev, "127.0.0.1")

		isBanned, _ := s.IsAuthorBanned(ctx, userA)
		require.False(t, isBanned, "No user should be banned when filter is disabled")
		require.Empty(t, cli.DeletedAuthors, "No deletes should happen when filter is disabled")
	})
}
