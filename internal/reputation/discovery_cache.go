package reputation

import (
	"sync"
	"time"

	"fiatjaf.com/nostr"
	kitrep "github.com/lessucettes/adresu-plugin/pkg/adresu-kit/reputation"
)

const (
	// Metadata is replaceable, so a cached latest copy is useful for a while.
	// Missing and failed lookups are retried much sooner, and never treated as
	// an empty relay or follow list.
	discoveryMetadataTTL = time.Hour
	discoveryRetryDelay  = 5 * time.Minute
)

// discoveryCache is worker-owned, bounded in-memory state. Every author entry
// count against max, including negative lookups, so a hostile graph cannot
// grow it past cfg.MaxNodes.
type discoveryCache struct {
	mu      sync.Mutex
	max     int
	entries map[nostr.PubKey]*discoveryEntry
}

type discoveryEntry struct {
	metadata    kitrep.RelayList
	hasMetadata bool
	checkedAt   time.Time
	lastMissing time.Time
	lastFailed  time.Time
	touched     time.Time
}

func newDiscoveryCache(max int) *discoveryCache {
	return &discoveryCache{max: max, entries: make(map[nostr.PubKey]*discoveryEntry)}
}

func (c *discoveryCache) cached(pk nostr.PubKey, now time.Time) (kitrep.RelayList, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry := c.entries[pk]
	if entry == nil || !entry.hasMetadata || now.Sub(entry.checkedAt) >= discoveryMetadataTTL {
		return kitrep.RelayList{}, false
	}
	return entry.metadata, true
}

func (c *discoveryCache) stale(pk nostr.PubKey) (kitrep.RelayList, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry := c.entries[pk]
	if entry == nil || !entry.hasMetadata {
		return kitrep.RelayList{}, false
	}
	return entry.metadata, true
}

func (c *discoveryCache) backoff(pk nostr.PubKey, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry := c.entries[pk]
	if entry == nil {
		return false
	}
	return recent(entry.lastMissing, now) || recent(entry.lastFailed, now)
}

func recent(at, now time.Time) bool {
	return !at.IsZero() && now.Sub(at) < discoveryRetryDelay
}

func (c *discoveryCache) putMetadata(pk nostr.PubKey, list kitrep.RelayList, now time.Time) {
	if c.max <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry := c.entries[pk]
	if entry == nil {
		entry = &discoveryEntry{}
		c.entries[pk] = entry
	}
	if entry.hasMetadata && !newerRelayMetadata(list, entry.metadata) {
		entry.checkedAt, entry.touched = now, now
		return
	}
	entry.metadata, entry.hasMetadata = list, true
	entry.checkedAt, entry.touched = now, now
	entry.lastMissing, entry.lastFailed = time.Time{}, time.Time{}
	c.pruneLocked(now)
}

func (c *discoveryCache) markMissing(pk nostr.PubKey, now time.Time) {
	c.mark(pk, now, true)
}

func (c *discoveryCache) markFailed(pk nostr.PubKey, now time.Time) {
	c.mark(pk, now, false)
}

func (c *discoveryCache) mark(pk nostr.PubKey, now time.Time, missing bool) {
	if c.max <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry := c.entries[pk]
	if entry == nil {
		entry = &discoveryEntry{}
		c.entries[pk] = entry
	}
	if missing {
		entry.lastMissing = now
	} else {
		entry.lastFailed = now
	}
	entry.touched = now
	c.pruneLocked(now)
}

func (c *discoveryCache) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

func (c *discoveryCache) pruneLocked(now time.Time) {
	if len(c.entries) <= c.max {
		return
	}
	for pk, entry := range c.entries {
		fresh := entry.hasMetadata && now.Sub(entry.checkedAt) < discoveryMetadataTTL
		if !fresh && !recent(entry.lastMissing, now) && !recent(entry.lastFailed, now) {
			delete(c.entries, pk)
		}
	}
	for len(c.entries) > c.max {
		var oldestKey nostr.PubKey
		var oldest time.Time
		first := true
		for pk, entry := range c.entries {
			if first || entry.touched.Before(oldest) {
				oldestKey, oldest, first = pk, entry.touched, false
			}
		}
		delete(c.entries, oldestKey)
	}
}
