package policy

import (
	"context"
	"strings"
	"time"

	lru "github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/lessucettes/adresu-kit/nip"
	kitpolicy "github.com/lessucettes/adresu-kit/policy"
	"github.com/nbd-wtf/go-nostr"
	"golang.org/x/sync/singleflight"

	"github.com/lessucettes/adresu-plugin/internal/config"
	"github.com/lessucettes/adresu-plugin/internal/store"
)

const (
	defaultCacheSize       = 8192
	defaultCacheTTL        = 5 * time.Minute
	bannedAuthorFilterName = "BannedAuthorFilter"
)

type BannedAuthorFilter struct {
	store store.Store
	cache *lru.LRU[string, bool]
	sf    singleflight.Group
	cfg   *config.BannedAuthorFilterConfig
}

func NewBannedAuthorFilter(s store.Store, cfg *config.BannedAuthorFilterConfig) (*BannedAuthorFilter, error) {
	cache := lru.NewLRU[string, bool](defaultCacheSize, nil, defaultCacheTTL)
	return &BannedAuthorFilter{
		store: s,
		cache: cache,
		cfg:   cfg,
	}, nil
}

func (f *BannedAuthorFilter) isBanned(ctx context.Context, pubkey string) (bool, error) {
	normalizedPubkey := strings.ToLower(pubkey)

	if isBanned, ok := f.cache.Get(normalizedPubkey); ok {
		return isBanned, nil
	}

	v, err, _ := f.sf.Do(normalizedPubkey, func() (any, error) {
		if isBanned, ok := f.cache.Get(normalizedPubkey); ok {
			return isBanned, nil
		}
		isBanned, err := f.store.IsAuthorBanned(ctx, normalizedPubkey)
		if err != nil {
			return false, err
		}
		f.cache.Add(normalizedPubkey, isBanned)
		return isBanned, nil
	})

	if err != nil {
		return false, err
	}
	return v.(bool), nil
}

func (f *BannedAuthorFilter) Match(ctx context.Context, event *nostr.Event, meta map[string]any) (kitpolicy.FilterResult, error) {
	newResult := kitpolicy.NewResultFunc(bannedAuthorFilterName)

	if event == nil {
		return newResult(false, "invalid_event", nil)
	}

	banned, err := f.isBanned(ctx, event.PubKey)
	if err != nil {
		return newResult(false, "internal_author_check_failed", err)
	}
	if banned {
		return newResult(false, "author_banned", nil)
	}

	if f.cfg != nil && f.cfg.CheckNIP26 {
		if delegationTag := event.Tags.Find("delegation"); delegationTag != nil {
			delegator, err := nip.ValidateDelegation(event)
			if err != nil {
				return newResult(false, "invalid_delegation", nil)
			}

			if delegator != "" {
				banned, err := f.isBanned(ctx, delegator)
				if err != nil {
					return newResult(false, "internal_delegator_check_failed", err)
				}
				if banned {
					return newResult(false, "delegator_banned", nil)
				}
			}
		}
	}

	return newResult(true, "author_not_banned", nil)
}
