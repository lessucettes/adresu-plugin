package policy

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"fiatjaf.com/nostr"

	"github.com/lessucettes/adresu-plugin/pkg/adresu-kit/nip"
	kitpolicy "github.com/lessucettes/adresu-plugin/pkg/adresu-kit/policy"

	"github.com/lessucettes/adresu-plugin/internal/store"
	"github.com/lessucettes/adresu-plugin/internal/strfry"
)

const moderationFilterName = "ModerationFilter"

type ModerationFilter struct {
	moderatorPubKey      nostr.PubKey
	banEmoji, unbanEmoji string
	store                store.Store
	sf                   strfry.ClientInterface
	banDuration          time.Duration

	wg sync.WaitGroup
}

func NewModerationFilter(moderatorPubKey, banEmoji, unbanEmoji string, s store.Store, sf strfry.ClientInterface, banDuration time.Duration) (*ModerationFilter, error) {
	var moderator nostr.PubKey
	if moderatorPubKey == "" || (banEmoji == "" && unbanEmoji == "") {
		slog.Warn("Moderation is disabled: no moderator key or no moderation emojis configured.")
	} else {
		if !nostr.IsValid32ByteHex(strings.ToLower(moderatorPubKey)) {
			return nil, fmt.Errorf("invalid moderator pubkey: expected 64 hex characters")
		}
		var err error
		moderator, err = nostr.PubKeyFromHex(moderatorPubKey)
		if err != nil {
			return nil, fmt.Errorf("invalid moderator pubkey: %w", err)
		}
	}
	return &ModerationFilter{
		moderatorPubKey: moderator,
		banEmoji:        banEmoji,
		unbanEmoji:      unbanEmoji,
		store:           s,
		sf:              sf,
		banDuration:     banDuration,
	}, nil
}

func (f *ModerationFilter) Match(ctx context.Context, event *nostr.Event, meta map[string]any) (kitpolicy.FilterResult, error) {
	newResult := kitpolicy.NewResultFunc(moderationFilterName)

	// The decoded event carries the author identity as a binary public key, so
	// no wire hex casing can produce a second spelling of the moderator.
	if f.moderatorPubKey == nostr.ZeroPK || event == nil || event.Kind != nostr.KindReaction ||
		event.PubKey != f.moderatorPubKey {
		return newResult(true, "Event is not a moderation action from the configured moderator.", nil)
	}

	// The signature covers the event body, not its ID field. A mismatch means
	// the event in front of us is not the immutable object the moderator signed.
	canonicalID := nip.CanonicalEventID(ctx, event)
	if event.ID != canonicalID {
		slog.Warn("Rejected moderation event whose ID does not match its signed content",
			"event_id", event.ID.Hex(), "canonical_id", canonicalID.Hex(), "pubkey", event.PubKey.Hex())
		return newResult(false, "Event ID does not match its signed content.", nil)
	}

	// Moderation actions have destructive side effects, so do not trust the
	// pubkey field alone; verify that the moderator actually signed the event.
	validSignature, err := nip.CheckEventSignature(ctx, event)
	if err != nil || !validSignature {
		slog.Warn("Rejected moderation event with an invalid signature",
			"event_id", event.ID.Hex(), "pubkey", event.PubKey.Hex(), "error", err)
		return newResult(false, "Event signature is invalid.", nil)
	}

	pTag := event.Tags.FindLast("p")
	if len(pTag) < 2 {
		return newResult(true, "Reaction has no target public key; moderation action was skipped.", nil)
	}

	// Decoding the target to a typed public key validates its curve point and
	// yields the canonical bytes used for self-ban checks and store keys.
	if !nostr.IsValid32ByteHex(strings.ToLower(pTag[1])) {
		return newResult(true, "Moderation target public key is invalid or belongs to the moderator; action was skipped.", nil)
	}
	pubkeyToModify, err := nostr.PubKeyFromHex(pTag[1])
	if err != nil || pubkeyToModify == f.moderatorPubKey {
		return newResult(true, "Moderation target public key is invalid or belongs to the moderator; action was skipped.", nil)
	}

	// meta may be nil when the filter is exercised directly.
	dryRun, _ := meta["dry_run"].(bool)

	// The canonical body hash identifies the action and is independent of any
	// wire hex casing; the ID field itself is not covered by the signature.
	actionID := canonicalID

	switch {
	case f.banEmoji != "" && event.Content == f.banEmoji:
		if dryRun {
			slog.Info("Dry-run: moderator ban was not applied", "banned_pubkey", pubkeyToModify.Hex())
			return newResult(true, "Dry-run: the moderator ban was not applied.", nil)
		}
		applied, err := f.store.ApplyModeration(ctx, actionID.Hex(), pubkeyToModify.Hex(), f.banDuration)
		if err != nil {
			return newResult(true, "Failed to ban the author targeted by the moderator.", err)
		}
		if !applied {
			return newResult(true, "This moderation action was already applied; the duplicate was ignored.", nil)
		}
		slog.Info("Moderator action: banning pubkey", "banned_pubkey", pubkeyToModify.Hex())
		f.wg.Add(1)
		go func() {
			defer f.wg.Done()
			if err := f.sf.DeleteEventsByAuthor(pubkeyToModify.Hex()); err != nil {
				slog.Error("Failed to delete events after moderator ban", "error", err, "pubkey", pubkeyToModify.Hex())
			}
		}()
		return newResult(true, "Author was banned at the moderator's request.", nil)

	case f.unbanEmoji != "" && event.Content == f.unbanEmoji:
		if dryRun {
			slog.Info("Dry-run: moderator unban was not applied", "unbanned_pubkey", pubkeyToModify.Hex())
			return newResult(true, "Dry-run: the moderator unban was not applied.", nil)
		}
		applied, err := f.store.ApplyModeration(ctx, actionID.Hex(), pubkeyToModify.Hex(), 0)
		if err != nil {
			return newResult(true, "Failed to unban the author targeted by the moderator.", err)
		}
		if !applied {
			return newResult(true, "This moderation action was already applied; the duplicate was ignored.", nil)
		}
		slog.Info("Moderator action: unbanning pubkey", "unbanned_pubkey", pubkeyToModify.Hex())
		return newResult(true, "Author was unbanned at the moderator's request.", nil)
	}

	return newResult(true, "Reaction does not match a configured moderation emoji; action was skipped.", nil)
}

// Close waits for pending event deletions. It must not be called concurrently
// with Match.
func (f *ModerationFilter) Close() error {
	f.wg.Wait()
	return nil
}
