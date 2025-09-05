// filter/banned_author_filter.go
package policy

import (
	"adresu-plugin/store"
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/nbd-wtf/go-nostr"
)

type BannedAuthorFilter struct {
	store store.Store
	cache *lru.LRU[string, bool]
	mu    sync.RWMutex
}

func NewBannedAuthorFilter(s store.Store) *BannedAuthorFilter {
	cache := lru.NewLRU[string, bool](8192, nil, 5*time.Minute)
	return &BannedAuthorFilter{
		store: s,
		cache: cache,
	}
}

func (f *BannedAuthorFilter) Name() string { return "BannedAuthorFilter" }

func (f *BannedAuthorFilter) Check(ctx context.Context, event *nostr.Event, remoteIP string) *Result {
	f.mu.RLock()
	if isBanned, ok := f.cache.Get(event.PubKey); ok {
		f.mu.RUnlock()
		if isBanned {
			slog.Warn("Rejecting event from banned author (cached)", "ip", remoteIP, "pubkey", event.PubKey, "event_id", event.ID)
			return Reject(fmt.Sprintf("blocked: author %s is banned", event.PubKey))
		}
		return Accept()
	}
	f.mu.RUnlock()

	f.mu.Lock()
	defer f.mu.Unlock()

	if isBanned, ok := f.cache.Get(event.PubKey); ok {
		if isBanned {
			return Reject(fmt.Sprintf("blocked: author %s is banned", event.PubKey))
		}
		return Accept()
	}

	isBanned, err := f.store.IsAuthorBanned(ctx, event.PubKey)
	if err != nil {
		slog.Error("Failed to check if author is banned", "pubkey", event.PubKey, "error", err)
		return Reject("internal: database error")
	}

	f.cache.Add(event.PubKey, isBanned)

	if isBanned {
		slog.Warn("Rejecting event from banned author (db)", "ip", remoteIP, "pubkey", event.PubKey, "event_id", event.ID)
		return Reject(fmt.Sprintf("blocked: author %s is banned", event.PubKey))
	}

	return Accept()
}
