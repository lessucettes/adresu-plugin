package policy

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"

	"github.com/lessucettes/adresu-plugin/internal/config"
	"github.com/lessucettes/adresu-plugin/internal/store"
)

func newModerationFilter(t *testing.T, moderatorPubKey, banEmoji, unbanEmoji string, s store.Store, sf *testStrfry) *ModerationFilter {
	t.Helper()

	filter, err := NewModerationFilter(moderatorPubKey, banEmoji, unbanEmoji, s, sf, 24*time.Hour)
	if err != nil {
		t.Fatalf("NewModerationFilter: %v", err)
	}
	return filter
}

func TestModerationFilterBansTargetAndDeletesEvents(t *testing.T) {
	moderatorSK, moderatorPubKey := newKeyPair(t)
	_, targetPubKey := newKeyPair(t)
	s := newTestStore()
	sf := &testStrfry{}
	filter := newModerationFilter(t, moderatorPubKey, "🔨", "🔓", s, sf)

	reaction := signedEvent(t, moderatorSK, nostr.KindReaction, "🔨", nostr.Tags{{"p", targetPubKey}})
	result, err := filter.Match(context.Background(), reaction, nil)
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if !result.Allowed {
		t.Fatalf("moderation reaction was rejected: %+v", result)
	}
	if !s.isBanned(targetPubKey) {
		t.Fatal("moderator ban was not applied")
	}
	waitFor(t, time.Second, func() bool { return sf.callCount() == 1 }, "event deletion was not triggered")
	if got := sf.callAuthors(); got[0] != targetPubKey {
		t.Fatalf("deleted author = %q, want %q", got[0], targetPubKey)
	}
}

func TestModerationFilterSupportsBanOnlyConfiguration(t *testing.T) {
	moderatorSK, moderatorPubKey := newKeyPair(t)
	_, targetPubKey := newKeyPair(t)
	s := newTestStore()
	sf := &testStrfry{}
	filter := newModerationFilter(t, moderatorPubKey, "🔨", "", s, sf)

	reaction := signedEvent(t, moderatorSK, nostr.KindReaction, "🔨", nostr.Tags{{"p", targetPubKey}})
	if _, err := filter.Match(context.Background(), reaction, nil); err != nil {
		t.Fatalf("Match: %v", err)
	}
	if !s.isBanned(targetPubKey) {
		t.Fatal("ban-only configuration did not apply the moderator ban")
	}
	waitFor(t, time.Second, func() bool { return sf.callCount() == 1 }, "ban-only configuration did not delete events")
}

func TestModerationFilterSupportsUnbanOnlyConfiguration(t *testing.T) {
	moderatorSK, moderatorPubKey := newKeyPair(t)
	_, targetPubKey := newKeyPair(t)
	s := newTestStore()
	filter := newModerationFilter(t, moderatorPubKey, "", "🔓", s, &testStrfry{})

	if err := s.BanAuthor(context.Background(), targetPubKey, time.Hour); err != nil {
		t.Fatalf("BanAuthor: %v", err)
	}
	reaction := signedEvent(t, moderatorSK, nostr.KindReaction, "🔓", nostr.Tags{{"p", targetPubKey}})
	if _, err := filter.Match(context.Background(), reaction, nil); err != nil {
		t.Fatalf("Match: %v", err)
	}
	if s.isBanned(targetPubKey) {
		t.Fatal("unban-only configuration did not apply the moderator unban")
	}

	// With no ban emoji configured, a reaction must not ban anyone.
	banReaction := signedEvent(t, moderatorSK, nostr.KindReaction, "🔨", nostr.Tags{{"p", targetPubKey}})
	if _, err := filter.Match(context.Background(), banReaction, nil); err != nil {
		t.Fatalf("Match: %v", err)
	}
	if s.isBanned(targetPubKey) {
		t.Fatal("unban-only configuration banned the target")
	}
}

func TestModerationFilterUnbansTarget(t *testing.T) {
	moderatorSK, moderatorPubKey := newKeyPair(t)
	_, targetPubKey := newKeyPair(t)
	s := newTestStore()
	filter := newModerationFilter(t, moderatorPubKey, "🔨", "🔓", s, &testStrfry{})

	if err := s.BanAuthor(context.Background(), targetPubKey, time.Hour); err != nil {
		t.Fatalf("BanAuthor: %v", err)
	}
	reaction := signedEvent(t, moderatorSK, nostr.KindReaction, "🔓", nostr.Tags{{"p", targetPubKey}})
	if _, err := filter.Match(context.Background(), reaction, nil); err != nil {
		t.Fatalf("Match: %v", err)
	}
	if s.isBanned(targetPubKey) {
		t.Fatal("moderator unban was not applied")
	}
}

func TestModerationFilterRejectsForgedModeratorEvent(t *testing.T) {
	_, moderatorPubKey := newKeyPair(t)
	attackerSK, _ := newKeyPair(t)
	_, targetPubKey := newKeyPair(t)
	s := newTestStore()
	sf := &testStrfry{}
	filter := newModerationFilter(t, moderatorPubKey, "🔨", "🔓", s, sf)

	// An attacker signs an event and claims the moderator's pubkey.
	reaction := signedEvent(t, attackerSK, nostr.KindReaction, "🔨", nostr.Tags{{"p", targetPubKey}})
	reaction.PubKey = moderatorPubKey

	result, err := filter.Match(context.Background(), reaction, nil)
	if err != nil {
		t.Fatalf("Match returned an operational error for a forged event: %v", err)
	}
	if result.Allowed {
		t.Fatal("event impersonating the moderator was accepted")
	}
	if s.isBanned(targetPubKey) {
		t.Fatal("forged moderator event triggered a ban")
	}
	if sf.callCount() != 0 {
		t.Fatal("forged moderator event triggered event deletion")
	}
}

func TestModerationFilterDryRunSkipsSideEffects(t *testing.T) {
	moderatorSK, moderatorPubKey := newKeyPair(t)
	_, targetPubKey := newKeyPair(t)
	s := newTestStore()
	sf := &testStrfry{}
	filter := newModerationFilter(t, moderatorPubKey, "🔨", "🔓", s, sf)

	reaction := signedEvent(t, moderatorSK, nostr.KindReaction, "🔨", nostr.Tags{{"p", targetPubKey}})
	result, err := filter.Match(context.Background(), reaction, map[string]any{"dry_run": true})
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if !result.Allowed {
		t.Fatalf("dry-run moderation reaction was rejected: %+v", result)
	}
	if s.isBanned(targetPubKey) || s.banCount() != 0 {
		t.Fatal("dry-run moderation wrote a ban")
	}
	if sf.callCount() != 0 {
		t.Fatal("dry-run moderation deleted events")
	}
}

func TestModerationFilterIgnoresEmptyEmoji(t *testing.T) {
	moderatorSK, moderatorPubKey := newKeyPair(t)
	_, targetPubKey := newKeyPair(t)
	s := newTestStore()
	filter := newModerationFilter(t, moderatorPubKey, "🔨", "", s, &testStrfry{})

	if err := s.BanAuthor(context.Background(), targetPubKey, time.Hour); err != nil {
		t.Fatalf("BanAuthor: %v", err)
	}

	// An empty reaction content must not match an unset unban emoji.
	reaction := signedEvent(t, moderatorSK, nostr.KindReaction, "", nostr.Tags{{"p", targetPubKey}})
	if _, err := filter.Match(context.Background(), reaction, nil); err != nil {
		t.Fatalf("Match: %v", err)
	}
	if !s.isBanned(targetPubKey) {
		t.Fatal("empty reaction content matched an unset unban emoji")
	}
}

func TestModerationFilterIgnoresNonModerator(t *testing.T) {
	_, moderatorPubKey := newKeyPair(t)
	otherSK, _ := newKeyPair(t)
	_, targetPubKey := newKeyPair(t)
	s := newTestStore()
	filter := newModerationFilter(t, moderatorPubKey, "🔨", "🔓", s, &testStrfry{})

	reaction := signedEvent(t, otherSK, nostr.KindReaction, "🔨", nostr.Tags{{"p", targetPubKey}})
	result, err := filter.Match(context.Background(), reaction, nil)
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if !result.Allowed || s.banCount() != 0 {
		t.Fatal("reaction from a non-moderator applied moderation")
	}
}

func TestModerationFilterSkipsInvalidTarget(t *testing.T) {
	moderatorSK, moderatorPubKey := newKeyPair(t)
	s := newTestStore()
	filter := newModerationFilter(t, moderatorPubKey, "🔨", "🔓", s, &testStrfry{})

	for _, target := range []string{"", "not-a-pubkey", moderatorPubKey} {
		reaction := signedEvent(t, moderatorSK, nostr.KindReaction, "🔨", nostr.Tags{{"p", target}})
		result, err := filter.Match(context.Background(), reaction, nil)
		if err != nil {
			t.Fatalf("Match target %q: %v", target, err)
		}
		if !result.Allowed || s.banCount() != 0 {
			t.Fatalf("invalid moderation target %q was acted upon", target)
		}
	}
}

func TestModerationFilterPropagatesBanFailure(t *testing.T) {
	moderatorSK, moderatorPubKey := newKeyPair(t)
	_, targetPubKey := newKeyPair(t)
	s := newTestStore()
	s.applyErr = errors.New("database unavailable")
	filter := newModerationFilter(t, moderatorPubKey, "🔨", "🔓", s, &testStrfry{})

	reaction := signedEvent(t, moderatorSK, nostr.KindReaction, "🔨", nostr.Tags{{"p", targetPubKey}})
	if _, err := filter.Match(context.Background(), reaction, nil); !errors.Is(err, s.applyErr) {
		t.Fatalf("Match error = %v, want %v", err, s.applyErr)
	}
}

func TestModerationFilterAppliesEachReactionOnce(t *testing.T) {
	moderatorSK, moderatorPubKey := newKeyPair(t)
	_, targetPubKey := newKeyPair(t)
	s := newTestStore()
	sf := &testStrfry{}
	filter := newModerationFilter(t, moderatorPubKey, "🔨", "🔓", s, sf)
	ctx := context.Background()

	reaction := signedEvent(t, moderatorSK, nostr.KindReaction, "🔨", nostr.Tags{{"p", targetPubKey}})

	// strfry's mesh paths (router/stream/sync) run the write policy before the
	// local duplicate check, so the same stored reaction can reach the plugin
	// again. Re-applying it would re-extend the ban and re-run a database-wide
	// deletion for anyone able to replay the signed event.
	for range 3 {
		result, err := filter.Match(ctx, reaction, nil)
		if err != nil {
			t.Fatalf("Match: %v", err)
		}
		if !result.Allowed {
			t.Fatalf("duplicate moderation reaction was rejected: %+v", result)
		}
	}
	if err := filter.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := s.banCount(); got != 1 {
		t.Fatalf("ban writes = %d, want 1 for one moderation event", got)
	}
	if got := sf.callCount(); got != 1 {
		t.Fatalf("event deletions = %d, want 1 for one moderation event", got)
	}

	// A distinct moderation action (a new signed event) must still be applied.
	second := *reaction
	second.CreatedAt = reaction.CreatedAt + 1
	if err := second.Sign(moderatorSK); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := filter.Match(ctx, &second, nil); err != nil {
		t.Fatalf("Match distinct action: %v", err)
	}
	if err := filter.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := s.banCount(); got != 2 {
		t.Fatalf("ban writes = %d, want 2 after a distinct moderation event", got)
	}
}

func TestModerationFilterDoesNotRevertUnbanOnReplay(t *testing.T) {
	moderatorSK, moderatorPubKey := newKeyPair(t)
	_, targetPubKey := newKeyPair(t)
	s := newTestStore()
	filter := newModerationFilter(t, moderatorPubKey, "🔨", "🔓", s, &testStrfry{})
	ctx := context.Background()

	ban := signedEvent(t, moderatorSK, nostr.KindReaction, "🔨", nostr.Tags{{"p", targetPubKey}})
	unban := signedEvent(t, moderatorSK, nostr.KindReaction, "🔓", nostr.Tags{{"p", targetPubKey}})
	if _, err := filter.Match(ctx, ban, nil); err != nil {
		t.Fatalf("Match ban: %v", err)
	}
	if _, err := filter.Match(ctx, unban, nil); err != nil {
		t.Fatalf("Match unban: %v", err)
	}
	if s.isBanned(targetPubKey) {
		t.Fatal("unban did not apply")
	}

	// Replaying the older ban reaction must not override the later unban.
	if _, err := filter.Match(ctx, ban, nil); err != nil {
		t.Fatalf("Match replayed ban: %v", err)
	}
	if err := filter.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if s.isBanned(targetPubKey) {
		t.Fatal("a replayed ban reaction re-banned an author the moderator unbanned")
	}
}

func TestModerationFilterRetriesAfterBanFailure(t *testing.T) {
	moderatorSK, moderatorPubKey := newKeyPair(t)
	_, targetPubKey := newKeyPair(t)
	s := newTestStore()
	s.applyErr = errors.New("database unavailable")
	filter := newModerationFilter(t, moderatorPubKey, "🔨", "🔓", s, &testStrfry{})
	ctx := context.Background()

	reaction := signedEvent(t, moderatorSK, nostr.KindReaction, "🔨", nostr.Tags{{"p", targetPubKey}})
	if _, err := filter.Match(ctx, reaction, nil); err == nil {
		t.Fatal("Match hid the ban failure")
	}

	// The failed action must not be remembered as applied, otherwise the
	// moderator cannot retry it.
	s.mu.Lock()
	s.applyErr = nil
	s.mu.Unlock()
	if _, err := filter.Match(ctx, reaction, nil); err != nil {
		t.Fatalf("retry after a failed ban: %v", err)
	}
	if err := filter.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !s.isBanned(targetPubKey) {
		t.Fatal("retrying a failed moderation action did not apply the ban")
	}
}

func TestModerationFilterBansAreVisibleToBannedAuthorFilter(t *testing.T) {
	moderatorSK, moderatorPubKey := newKeyPair(t)
	_, targetPubKey := newKeyPair(t)
	s := newTestStore()

	bannedFilter, err := NewBannedAuthorFilter(s, &config.BannedAuthorFilterConfig{})
	if err != nil {
		t.Fatalf("NewBannedAuthorFilter: %v", err)
	}
	moderationFilter := newModerationFilter(t, moderatorPubKey, "🔨", "🔓", s, &testStrfry{})
	ctx := context.Background()

	authorEvent := signedEvent(t, moderatorSK, nostr.KindTextNote, "hello", nil)
	authorEvent.PubKey = targetPubKey // signature validity is irrelevant for this filter

	result, err := bannedFilter.Match(ctx, authorEvent, nil)
	if err != nil || !result.Allowed {
		t.Fatalf("prime Match = %+v, %v; want allowed", result, err)
	}

	reaction := signedEvent(t, moderatorSK, nostr.KindReaction, "🔨", nostr.Tags{{"p", targetPubKey}})
	if _, err := moderationFilter.Match(ctx, reaction, nil); err != nil {
		t.Fatalf("moderation Match: %v", err)
	}

	result, err = bannedFilter.Match(ctx, authorEvent, nil)
	if err != nil {
		t.Fatalf("Match after ban: %v", err)
	}
	if result.Allowed {
		t.Fatal("moderator ban was not visible to the banned-author filter")
	}
}

func TestModerationFilterMatchesUppercaseSignedAuthorAndTarget(t *testing.T) {
	moderatorSK, moderatorPubKey := newKeyPair(t)
	_, targetPubKey := newKeyPair(t)
	s := newTestStore()
	sf := &testStrfry{}
	filter := newModerationFilter(t, strings.ToLower(moderatorPubKey), "🔨", "🔓", s, sf)

	// Signatures cover the exact pubkey spelling, so the event must be signed
	// independently after choosing uppercase hex for both the author and target.
	// evt.Sign would reset PubKey and hide the case-sensitivity bug.
	reaction := signedEventWithPubkey(t, moderatorSK, strings.ToUpper(moderatorPubKey), nostr.KindReaction, "🔨",
		nostr.Tags{{"p", strings.ToUpper(targetPubKey)}})

	result, err := filter.Match(context.Background(), reaction, nil)
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if !result.Allowed {
		t.Fatalf("uppercase moderation reaction was rejected: %+v", result)
	}
	if !s.isBanned(targetPubKey) {
		t.Fatal("uppercase target was not normalized before the ban was stored")
	}
	waitFor(t, time.Second, func() bool { return sf.callCount() == 1 }, "uppercase target did not trigger event deletion")
	if got := sf.callAuthors(); got[0] != targetPubKey {
		t.Fatalf("deleted author = %q, want normalized %q", got[0], targetPubKey)
	}
}

func TestModerationFilterSkipsUppercaseSelfTarget(t *testing.T) {
	moderatorSK, moderatorPubKey := newKeyPair(t)
	s := newTestStore()
	sf := &testStrfry{}
	filter := newModerationFilter(t, moderatorPubKey, "🔨", "🔓", s, sf)

	reaction := signedEventWithPubkey(t, moderatorSK, strings.ToUpper(moderatorPubKey), nostr.KindReaction, "🔨",
		nostr.Tags{{"p", strings.ToUpper(moderatorPubKey)}})

	result, err := filter.Match(context.Background(), reaction, nil)
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if !result.Allowed || s.banCount() != 0 || sf.callCount() != 0 {
		t.Fatal("uppercase self-target was acted upon instead of being skipped")
	}
	if s.isBanned(moderatorPubKey) {
		t.Fatal("moderator was banned through an uppercase self-target")
	}
}

func TestModerationReplayPersistsAcrossFilterRecreationAndStoreReopen(t *testing.T) {
	moderatorSK, moderatorPubKey := newKeyPair(t)
	_, targetPubKey := newKeyPair(t)
	dbPath := t.TempDir()

	openStore := func() *store.BadgerStore {
		t.Helper()
		db, err := store.NewBadgerStore(&config.DBConfig{Path: dbPath})
		if err != nil {
			t.Fatalf("NewBadgerStore: %v", err)
		}
		return db
	}
	closeStore := func(db *store.BadgerStore) {
		t.Helper()
		if err := db.Close(); err != nil {
			t.Fatalf("Close store: %v", err)
		}
	}

	db := openStore()
	sf := &testStrfry{}
	ctx := context.Background()
	filter := newModerationFilter(t, moderatorPubKey, "🔨", "🔓", db, sf)

	ban := signedEvent(t, moderatorSK, nostr.KindReaction, "🔨", nostr.Tags{{"p", targetPubKey}})
	unban := signedEvent(t, moderatorSK, nostr.KindReaction, "🔓", nostr.Tags{{"p", targetPubKey}})

	if _, err := filter.Match(ctx, ban, nil); err != nil {
		t.Fatalf("Match ban: %v", err)
	}
	waitFor(t, time.Second, func() bool { return sf.callCount() == 1 }, "initial ban did not delete events")
	if _, err := filter.Match(ctx, unban, nil); err != nil {
		t.Fatalf("Match unban: %v", err)
	}
	if err := filter.Close(); err != nil {
		t.Fatalf("Close first filter: %v", err)
	}
	if banned, err := db.IsAuthorBanned(ctx, targetPubKey); err != nil {
		t.Fatalf("IsAuthorBanned: %v", err)
	} else if banned {
		t.Fatal("unban did not apply")
	}

	// A reloaded pipeline gets a new filter. The already-applied ban must remain
	// suppressed even though the filter-local state was discarded.
	filter = newModerationFilter(t, moderatorPubKey, "🔨", "🔓", db, sf)
	if _, err := filter.Match(ctx, ban, nil); err != nil {
		t.Fatalf("Match replayed ban after filter recreation: %v", err)
	}
	if err := filter.Close(); err != nil {
		t.Fatalf("Close recreated filter: %v", err)
	}
	if banned, err := db.IsAuthorBanned(ctx, targetPubKey); err != nil {
		t.Fatalf("IsAuthorBanned after replay: %v", err)
	} else if banned {
		t.Fatal("a replayed ban reaction re-banned the author after filter recreation")
	}
	if got := sf.callCount(); got != 1 {
		t.Fatalf("event deletions after filter recreation = %d, want 1", got)
	}

	// Restart the process: the action marker and the ban state must survive in
	// Badger, not in the filter's process memory.
	closeStore(db)
	db = openStore()
	defer closeStore(db)
	filter = newModerationFilter(t, moderatorPubKey, "🔨", "🔓", db, sf)
	if _, err := filter.Match(ctx, ban, nil); err != nil {
		t.Fatalf("Match replayed ban after store reopen: %v", err)
	}
	if _, err := filter.Match(ctx, unban, nil); err != nil {
		t.Fatalf("Match replayed unban after store reopen: %v", err)
	}
	if err := filter.Close(); err != nil {
		t.Fatalf("Close filter after reopen: %v", err)
	}
	if banned, err := db.IsAuthorBanned(ctx, targetPubKey); err != nil {
		t.Fatalf("IsAuthorBanned after reopen: %v", err)
	} else if banned {
		t.Fatal("a replayed ban reaction re-banned the author after store reopen")
	}
	if got := sf.callCount(); got != 1 {
		t.Fatalf("event deletions after store reopen = %d, want 1", got)
	}

	// A distinct moderation event must still be applied after the replays.
	distinct := signedEvent(t, moderatorSK, nostr.KindReaction, "🔨", nostr.Tags{{"p", targetPubKey}})
	distinct.CreatedAt = ban.CreatedAt + 1
	if err := distinct.Sign(moderatorSK); err != nil {
		t.Fatalf("Sign distinct action: %v", err)
	}
	if _, err := filter.Match(ctx, distinct, nil); err != nil {
		t.Fatalf("Match distinct action: %v", err)
	}
	if err := filter.Close(); err != nil {
		t.Fatalf("Close filter after distinct action: %v", err)
	}
	if banned, err := db.IsAuthorBanned(ctx, targetPubKey); err != nil {
		t.Fatalf("IsAuthorBanned after distinct action: %v", err)
	} else if !banned {
		t.Fatal("a distinct moderation action was not applied")
	}
	if got := sf.callCount(); got != 2 {
		t.Fatalf("event deletions after distinct action = %d, want 2", got)
	}
}

func TestModerationActionRetriesAfterCanceledStoreTransaction(t *testing.T) {
	moderatorSK, moderatorPubKey := newKeyPair(t)
	_, targetPubKey := newKeyPair(t)
	db, err := store.NewBadgerStore(&config.DBConfig{Path: t.TempDir()})
	if err != nil {
		t.Fatalf("NewBadgerStore: %v", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			t.Fatalf("Close store: %v", err)
		}
	}()
	sf := &testStrfry{}
	filter := newModerationFilter(t, moderatorPubKey, "🔨", "🔓", db, sf)
	ctx := context.Background()

	reaction := signedEvent(t, moderatorSK, nostr.KindReaction, "🔨", nostr.Tags{{"p", targetPubKey}})
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := filter.Match(canceled, reaction, nil); err == nil {
		t.Fatal("Match hid a failed store transaction")
	}
	if banned, err := db.IsAuthorBanned(ctx, targetPubKey); err != nil {
		t.Fatalf("IsAuthorBanned after failure: %v", err)
	} else if banned {
		t.Fatal("failed transaction applied a partial ban")
	}
	if sf.callCount() != 0 {
		t.Fatal("failed transaction triggered event deletion")
	}

	// The same signed action remains retryable because no marker was committed.
	if _, err := filter.Match(ctx, reaction, nil); err != nil {
		t.Fatalf("Match retry: %v", err)
	}
	if err := filter.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if banned, err := db.IsAuthorBanned(ctx, targetPubKey); err != nil {
		t.Fatalf("IsAuthorBanned after retry: %v", err)
	} else if !banned {
		t.Fatal("retry after a failed transaction did not apply the ban")
	}
	if sf.callCount() != 1 {
		t.Fatalf("event deletions after retry = %d, want 1", sf.callCount())
	}
}
