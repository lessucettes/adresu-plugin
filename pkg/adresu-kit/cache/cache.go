// Package cache provides a bounded least-recently-used cache with lazy
// per-entry expiration.
//
// Unlike github.com/hashicorp/golang-lru/v2/expirable, this cache starts no
// background goroutines and therefore needs no Close method. Expired entries
// are discarded when they are accessed, overwritten, or evicted by the size
// limit, so abandoned caches (for example, after a configuration reload) do
// not leak resources and sub-millisecond TTLs cannot panic a ticker.
package cache

import (
	"math"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
)

type entry[V any] struct {
	value     V
	expiresAt time.Time
}

// LRU is a concurrency-safe LRU cache with a time-to-live per entry.
// LRU must not be copied after first use.
type LRU[K comparable, V any] struct {
	mu  sync.Mutex
	c   *lru.Cache[K, entry[V]]
	ttl time.Duration
}

// NewLRU creates a cache that holds at most size entries. As with the
// expirable cache it replaces, size <= 0 means no size limit and ttl <= 0
// disables expiration. Entries expire ttl after they are added; re-adding a
// key refreshes its expiration while reading it does not.
func NewLRU[K comparable, V any](size int, ttl time.Duration) *LRU[K, V] {
	if size <= 0 {
		size = math.MaxInt
	}
	c, err := lru.New[K, entry[V]](size)
	if err != nil {
		// Only non-positive sizes are rejected, and those are mapped above.
		panic("cache: cannot create LRU: " + err.Error())
	}
	return &LRU[K, V]{c: c, ttl: ttl}
}

// Add inserts or updates key, renewing its expiration, and reports whether
// the size limit forced an eviction.
func (c *LRU[K, V]) Add(key K, value V) (evicted bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	e := entry[V]{value: value}
	if c.ttl > 0 {
		e.expiresAt = time.Now().Add(c.ttl)
	}
	return c.c.Add(key, e)
}

// Get returns the value for key and marks it as recently used. An expired
// entry is removed and reported as missing.
func (c *LRU[K, V]) Get(key K) (value V, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	e, ok := c.c.Get(key)
	if !ok {
		var zero V
		return zero, false
	}
	if c.ttl > 0 && time.Now().After(e.expiresAt) {
		c.c.Remove(key)
		var zero V
		return zero, false
	}
	return e.value, true
}

// Remove deletes key and reports whether it was present.
func (c *LRU[K, V]) Remove(key K) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.c.Remove(key)
}

// Len returns the number of retained entries, including expired entries that
// have not been accessed or evicted yet.
func (c *LRU[K, V]) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.c.Len()
}

// Purge removes every entry.
func (c *LRU[K, V]) Purge() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.c.Purge()
}
