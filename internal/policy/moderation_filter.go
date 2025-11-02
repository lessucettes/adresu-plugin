package policy

import (
	"context"
	"log/slog"
	"time"

	kitpolicy "github.com/lessucettes/adresu-plugin/pkg/adresu-kit/policy"
	"github.com/nbd-wtf/go-nostr"

	"github.com/lessucettes/adresu-plugin/internal/store"
	"github.com/lessucettes/adresu-plugin/internal/strfry"
)

const (
	moderationFilterName = "ModerationFilter"
)

type ModerationFilter struct {
	moderatorPubKey, banEmoji, unbanEmoji string
	store                                 store.Store
	sf                                    strfry.ClientInterface
	banDuration                           time.Duration
}

func NewModerationFilter(moderatorPubKey, banEmoji, unbanEmoji string, s store.Store, sf strfry.ClientInterface, banDuration time.Duration) (*ModerationFilter, error) {
	if moderatorPubKey == "" {
		slog.Warn("Policy.moderator_pubkey is not set in config, moderation filter will be disabled.")
	}
	return &ModerationFilter{
		moderatorPubKey: moderatorPubKey,
		banEmoji:        banEmoji,
		unbanEmoji:      unbanEmoji,
		store:           s,
		sf:              sf,
		banDuration:     banDuration,
	}, nil
}

func (f *ModerationFilter) Match(ctx context.Context, event *nostr.Event, meta map[string]any) (kitpolicy.FilterResult, error) {
	newResult := kitpolicy.NewResultFunc(moderationFilterName)

	if f.moderatorPubKey == "" || event.Kind != nostr.KindReaction || event.PubKey != f.moderatorPubKey {
		return newResult(true, "not_a_moderation_event", nil)
	}

	pTag := event.Tags.FindLast("p")
	if len(pTag) < 2 {
		return newResult(true, "no_pubkey_tag_in_reaction", nil)
	}

	pubkeyToModify := pTag[1]
	if !nostr.IsValidPublicKey(pubkeyToModify) || pubkeyToModify == f.moderatorPubKey {
		return newResult(true, "invalid_target_pubkey", nil)
	}

	switch event.Content {
	case f.banEmoji:
		slog.Info("Moderator action: banning pubkey", "banned_pubkey", pubkeyToModify)
		if err := f.store.BanAuthor(ctx, pubkeyToModify, f.banDuration); err != nil {
			// A side-effect failed. Propagate the error to the pipeline.
			return newResult(true, "moderator_ban_failed", err)
		}
		go func() {
			if err := f.sf.DeleteEventsByAuthor(pubkeyToModify); err != nil {
				slog.Error("Failed to delete events after moderator ban", "error", err, "pubkey", pubkeyToModify)
			}
		}()
		return newResult(true, "moderator_ban_executed", nil)

	case f.unbanEmoji:
		slog.Info("Moderator action: unbanning pubkey", "unbanned_pubkey", pubkeyToModify)
		if err := f.store.UnbanAuthor(ctx, pubkeyToModify); err != nil {
			return newResult(true, "moderator_unban_failed", err)
		}
		return newResult(true, "moderator_unban_executed", nil)
	}

	return newResult(true, "emoji_not_matched", nil)
}
