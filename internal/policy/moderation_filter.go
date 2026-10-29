package policy

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	kitpolicy "github.com/lessucettes/adresu-plugin/pkg/adresu-kit/policy"
	"github.com/nbd-wtf/go-nostr"

	"github.com/lessucettes/adresu-plugin/internal/store"
	"github.com/lessucettes/adresu-plugin/internal/strfry"
)

const moderationFilterName = "ModerationFilter"

type ModerationFilter struct {
	moderatorPubKey, banEmoji, unbanEmoji string
	store                                 store.Store
	sf                                    strfry.ClientInterface
	banDuration                           time.Duration

	wg sync.WaitGroup
}

func NewModerationFilter(moderatorPubKey, banEmoji, unbanEmoji string, s store.Store, sf strfry.ClientInterface, banDuration time.Duration) (*ModerationFilter, error) {
	if moderatorPubKey == "" {
		slog.Warn("Policy.moderator_pubkey is not set in config, moderation filter will be disabled.")
	}
	return &ModerationFilter{
		moderatorPubKey: strings.ToLower(moderatorPubKey),
		banEmoji:        banEmoji,
		unbanEmoji:      unbanEmoji,
		store:           s,
		sf:              sf,
		banDuration:     banDuration,
	}, nil
}

func (f *ModerationFilter) Match(ctx context.Context, event *nostr.Event, meta map[string]any) (kitpolicy.FilterResult, error) {
	newResult := kitpolicy.NewResultFunc(moderationFilterName)

	// Compare without rewriting the signed event. The event body, including
	// its pubkey spelling, is covered by the signature.
	if f.moderatorPubKey == "" || event == nil || event.Kind != nostr.KindReaction ||
		!strings.EqualFold(event.PubKey, f.moderatorPubKey) {
		return newResult(true, "Event is not a moderation action from the configured moderator.", nil)
	}

	// Moderation actions have destructive side effects, so do not trust the
	// pubkey field alone; verify that the moderator actually signed the event.
	validSignature, err := event.CheckSignature()
	if err != nil || !validSignature {
		slog.Warn("Rejected moderation event with an invalid signature",
			"event_id", event.ID, "pubkey", event.PubKey, "error", err)
		return newResult(false, "Event signature is invalid.", nil)
	}

	pTag := event.Tags.FindLast("p")
	if len(pTag) < 2 {
		return newResult(true, "Reaction has no target public key; moderation action was skipped.", nil)
	}

	// Store and strfry keys are canonical lowercase, so normalize the target
	// before validating it, checking for a self-ban, and applying side effects.
	pubkeyToModify := strings.ToLower(pTag[1])
	if !nostr.IsValidPublicKey(pubkeyToModify) || pubkeyToModify == f.moderatorPubKey {
		return newResult(true, "Moderation target public key is invalid or belongs to the moderator; action was skipped.", nil)
	}

	// meta may be nil when the filter is exercised directly.
	dryRun, _ := meta["dry_run"].(bool)

	// The canonical body hash identifies the action; the ID field is attacker
	// controlled and is not covered by the signature.
	actionID := event.GetID()

	switch {
	case f.banEmoji != "" && event.Content == f.banEmoji:
		if dryRun {
			slog.Info("Dry-run: moderator ban was not applied", "banned_pubkey", pubkeyToModify)
			return newResult(true, "Dry-run: the moderator ban was not applied.", nil)
		}
		applied, err := f.store.ApplyModeration(ctx, actionID, pubkeyToModify, f.banDuration)
		if err != nil {
			return newResult(true, "Failed to ban the author targeted by the moderator.", err)
		}
		if !applied {
			return newResult(true, "This moderation action was already applied; the duplicate was ignored.", nil)
		}
		slog.Info("Moderator action: banning pubkey", "banned_pubkey", pubkeyToModify)
		f.wg.Add(1)
		go func() {
			defer f.wg.Done()
			if err := f.sf.DeleteEventsByAuthor(pubkeyToModify); err != nil {
				slog.Error("Failed to delete events after moderator ban", "error", err, "pubkey", pubkeyToModify)
			}
		}()
		return newResult(true, "Author was banned at the moderator's request.", nil)

	case f.unbanEmoji != "" && event.Content == f.unbanEmoji:
		if dryRun {
			slog.Info("Dry-run: moderator unban was not applied", "unbanned_pubkey", pubkeyToModify)
			return newResult(true, "Dry-run: the moderator unban was not applied.", nil)
		}
		applied, err := f.store.ApplyModeration(ctx, actionID, pubkeyToModify, 0)
		if err != nil {
			return newResult(true, "Failed to unban the author targeted by the moderator.", err)
		}
		if !applied {
			return newResult(true, "This moderation action was already applied; the duplicate was ignored.", nil)
		}
		slog.Info("Moderator action: unbanning pubkey", "unbanned_pubkey", pubkeyToModify)
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
