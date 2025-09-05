// policy/moderation_filter.go
package policy

import (
	"adresu-plugin/store"
	"adresu-plugin/strfry"
	"context"
	"log/slog"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

type ModerationFilter struct {
	moderatorPubKey, banEmoji, unbanEmoji string
	store                                 store.Store
	sf                                    strfry.ClientInterface
	banDuration                           time.Duration
}

func NewModerationFilter(moderatorPubKey, banEmoji, unbanEmoji string, s store.Store, sf strfry.ClientInterface, banDuration time.Duration) *ModerationFilter {
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
	}
}
func (f *ModerationFilter) Name() string { return "ModerationFilter" }

func (f *ModerationFilter) Check(ctx context.Context, event *nostr.Event, remoteIP string) *Result {
	if f.moderatorPubKey == "" || event.Kind != nostr.KindReaction || event.PubKey != f.moderatorPubKey {
		return Accept()
	}
	pTag := event.Tags.FindLast("p")
	if len(pTag) < 2 {
		return Accept()
	}
	pubkeyToModify := pTag[1]
	if !nostr.IsValidPublicKey(pubkeyToModify) || pubkeyToModify == f.moderatorPubKey {
		return Accept()
	}
	switch event.Content {
	case f.banEmoji:
		slog.Info("Moderator action: banning pubkey", "banned_pubkey", pubkeyToModify)
		if err := f.store.BanAuthor(ctx, pubkeyToModify, f.banDuration); err != nil {
			slog.Error("Moderation failed to save ban", "error", err, "banned_pubkey", pubkeyToModify)
		}
		go f.sf.DeleteEventsByAuthor(pubkeyToModify)
	case f.unbanEmoji:
		slog.Info("Moderator action: unbanning pubkey", "unbanned_pubkey", pubkeyToModify)
		if err := f.store.UnbanAuthor(ctx, pubkeyToModify); err != nil {
			slog.Error("Moderation failed to remove ban", "error", err, "unbanned_pubkey", pubkeyToModify)
		}
	}
	return Accept()
}
