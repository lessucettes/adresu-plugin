package policy

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/lessucettes/adresu-plugin/config"
	"github.com/lessucettes/adresu-plugin/store"

	lru "github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/lessucettes/adresu-kit/nip"
	"github.com/nbd-wtf/go-nostr"
	"golang.org/x/sync/singleflight"
)

const (
	defaultCacheSize = 8192
	defaultCacheTTL  = 5 * time.Minute
)

type BannedAuthorFilter struct {
	store store.Store
	cache *lru.LRU[string, bool]
	sf    singleflight.Group
	cfg   *config.BannedAuthorFilterConfig
}

func NewBannedAuthorFilter(s store.Store, cfg *config.BannedAuthorFilterConfig) *BannedAuthorFilter {
	cache := lru.NewLRU[string, bool](defaultCacheSize, nil, defaultCacheTTL)
	return &BannedAuthorFilter{
		store: s,
		cache: cache,
		cfg:   cfg,
	}
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

func (f *BannedAuthorFilter) Match(ctx context.Context, event *nostr.Event, meta map[string]any) (bool, error) {
	if event == nil {
		return false, fmt.Errorf("blocked: invalid event")
	}

	banned, err := f.isBanned(ctx, event.PubKey)
	if err != nil {
		slog.Error("Failed to check author ban status, rejecting (fail-closed)", "pubkey", event.PubKey, "error", err)
		return false, fmt.Errorf("internal: verification error")
	}
	if banned {
		return false, fmt.Errorf("blocked: author %s is banned", event.PubKey)
	}

	if f.cfg != nil && f.cfg.CheckNIP26 {
		if delegationTag := event.Tags.Find("delegation"); delegationTag != nil {
			delegator, err := nip.ValidateDelegation(event)
			if err != nil {
				return false, fmt.Errorf("blocked: invalid delegation: %w", err)
			}

			if delegator != "" {
				banned, err := f.isBanned(ctx, delegator)
				if err != nil {
					slog.Error("Failed to check delegator ban status", "delegator", delegator, "error", err)
					return false, fmt.Errorf("internal: verification error")
				}
				if banned {
					return false, fmt.Errorf("blocked: delegator %s is banned", delegator)
				}
			}
		}
	}

	return true, nil
}
