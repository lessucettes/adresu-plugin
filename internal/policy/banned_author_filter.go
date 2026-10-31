package policy

import (
	"context"

	"fiatjaf.com/nostr"

	"github.com/lessucettes/adresu-plugin/pkg/adresu-kit/nip"
	kitpolicy "github.com/lessucettes/adresu-plugin/pkg/adresu-kit/policy"

	"github.com/lessucettes/adresu-plugin/internal/config"
	"github.com/lessucettes/adresu-plugin/internal/store"
)

const bannedAuthorFilterName = "BannedAuthorFilter"

type BannedAuthorFilter struct {
	store store.Store
	cfg   *config.BannedAuthorFilterConfig
}

func NewBannedAuthorFilter(s store.Store, cfg *config.BannedAuthorFilterConfig) (*BannedAuthorFilter, error) {
	return &BannedAuthorFilter{
		store: s,
		cfg:   cfg,
	}, nil
}

// isBanned reads the authoritative ban state from the store on every event.
// Badger already caches hot keys internally, and a filter-local cache would
// keep authors publishable for its TTL after a moderator ban and keep
// unbanned authors rejected after an unban.
func (f *BannedAuthorFilter) isBanned(ctx context.Context, pubkey nostr.PubKey) (bool, error) {
	return f.store.IsAuthorBanned(ctx, pubkey.Hex())
}

func (f *BannedAuthorFilter) Match(ctx context.Context, event *nostr.Event, meta map[string]any) (kitpolicy.FilterResult, error) {
	newResult := kitpolicy.NewResultFunc(bannedAuthorFilterName)

	if event == nil {
		return newResult(false, "Event is missing.", nil)
	}

	banned, err := f.isBanned(ctx, event.PubKey)
	if err != nil {
		return newResult(false, "Failed to check whether the event author is banned.", err)
	}
	if banned {
		return newResult(false, "The event author is banned from this relay.", nil)
	}

	if f.cfg != nil && f.cfg.CheckNIP26 {
		// An event can carry several delegation tags; every one of them names
		// an author who took part in publishing it, so a single ignored tag
		// lets a banned delegator hide behind a permitted one.
		for _, delegationTag := range event.Tags {
			if len(delegationTag) == 0 || delegationTag[0] != "delegation" {
				continue
			}

			delegator, err := nip.ValidateDelegationTag(ctx, event, delegationTag)
			if err != nil {
				return newResult(false, "Event delegation is invalid.", nil)
			}
			if delegator == "" {
				continue
			}

			delegatorPubKey, err := nostr.PubKeyFromHex(delegator)
			if err != nil {
				return newResult(false, "Event delegation is invalid.", nil)
			}
			banned, err := f.isBanned(ctx, delegatorPubKey)
			if err != nil {
				return newResult(false, "Failed to check whether the delegating author is banned.", err)
			}
			if banned {
				return newResult(false, "The delegating author is banned from this relay.", nil)
			}
		}
	}

	return newResult(true, "No ban was found for the event author or any checked delegating author.", nil)
}
