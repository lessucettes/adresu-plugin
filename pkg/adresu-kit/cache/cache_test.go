package cache_test

import (
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/lessucettes/adresu-plugin/pkg/adresu-kit/cache"
)

const testTTL = 250 * time.Millisecond

func TestGetExpiresAfterTTL(t *testing.T) {
	c := cache.NewLRU[string, int](10, testTTL)
	c.Add("k", 1)

	if v, ok := c.Get("k"); !ok || v != 1 {
		t.Fatalf("Get before expiry = (%d, %v), want (1, true)", v, ok)
	}

	time.Sleep(3 * testTTL / 2)

	if _, ok := c.Get("k"); ok {
		t.Fatal("Get after TTL returned an entry")
	}
	if got := c.Len(); got != 0 {
		t.Fatalf("Len after expired Get = %d, want 0", got)
	}
}

func TestAddRefreshesTTL(t *testing.T) {
	c := cache.NewLRU[string, int](10, testTTL)
	c.Add("k", 1)

	time.Sleep(3 * testTTL / 4)
	c.Add("k", 2)               // Refreshes the expiration.
	time.Sleep(3 * testTTL / 4) // Past the original expiry, before the renewed one.

	if v, ok := c.Get("k"); !ok || v != 2 {
		t.Fatalf("Get after refreshed TTL = (%d, %v), want (2, true)", v, ok)
	}

	time.Sleep(3 * testTTL / 2)

	if _, ok := c.Get("k"); ok {
		t.Fatal("Get long after refreshed TTL returned an entry")
	}
}

func TestGetDoesNotRefreshTTL(t *testing.T) {
	c := cache.NewLRU[string, int](10, testTTL)
	c.Add("k", 1)

	time.Sleep(3 * testTTL / 4)
	if _, ok := c.Get("k"); !ok {
		t.Fatal("Get before expiry missed the entry")
	}
	time.Sleep(3 * testTTL / 4) // A read-refreshed entry would still be alive here.

	if _, ok := c.Get("k"); ok {
		t.Fatal("Get extended the entry's lifetime")
	}
}

func TestBoundedEviction(t *testing.T) {
	c := cache.NewLRU[string, int](2, 0)
	c.Add("a", 1)
	c.Add("b", 2)
	c.Add("c", 3)

	if got := c.Len(); got != 2 {
		t.Fatalf("Len = %d, want 2", got)
	}
	if _, ok := c.Get("a"); ok {
		t.Fatal("least recently used entry was not evicted")
	}
	if v, ok := c.Get("c"); !ok || v != 3 {
		t.Fatalf("Get(c) = (%d, %v), want (3, true)", v, ok)
	}
}

func TestNonPositiveSizeIsUnlimited(t *testing.T) {
	c := cache.NewLRU[int, int](0, 0)
	for i := 0; i < 1000; i++ {
		c.Add(i, i)
	}
	if got := c.Len(); got != 1000 {
		t.Fatalf("Len = %d, want 1000", got)
	}
}

func TestNonPositiveTTLNeverExpires(t *testing.T) {
	c := cache.NewLRU[string, int](10, 0)
	c.Add("k", 1)
	time.Sleep(20 * time.Millisecond)
	if v, ok := c.Get("k"); !ok || v != 1 {
		t.Fatalf("Get with TTL 0 = (%d, %v), want (1, true)", v, ok)
	}
}

// A tiny TTL must not start a ticker that panics asynchronously.
func TestTinyTTLDoesNotPanic(t *testing.T) {
	c := cache.NewLRU[string, int](10, time.Nanosecond)
	c.Add("k", 1)
	c.Get("k")
	time.Sleep(10 * time.Millisecond)
}

func TestRemoveAndPurge(t *testing.T) {
	c := cache.NewLRU[string, int](10, 0)
	c.Add("a", 1)
	c.Add("b", 2)

	if !c.Remove("a") {
		t.Fatal("Remove reported a missing key")
	}
	if c.Remove("a") {
		t.Fatal("Remove reported a removed key as present")
	}
	if _, ok := c.Get("a"); ok {
		t.Fatal("removed key is still readable")
	}

	c.Purge()
	if got := c.Len(); got != 0 {
		t.Fatalf("Len after Purge = %d, want 0", got)
	}
}

func TestConcurrentAccessStaysBounded(t *testing.T) {
	const size = 64
	c := cache.NewLRU[int, int](size, time.Minute)

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(offset int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				key := (offset*500 + i) % 256
				c.Add(key, key)
				c.Get(key)
				if i%7 == 0 {
					c.Remove(key)
				}
			}
		}(g)
	}
	wg.Wait()

	if got := c.Len(); got > size {
		t.Fatalf("Len = %d, want <= %d", got, size)
	}
}

// The previous cache implementation started one immortal goroutine per cache,
// leaking them on every configuration reload.
func TestNoBackgroundGoroutines(t *testing.T) {
	runtime.GC()
	before := runtime.NumGoroutine()

	caches := make([]*cache.LRU[int, int], 0, 100)
	for i := 0; i < 100; i++ {
		c := cache.NewLRU[int, int](16, time.Minute)
		c.Add(i, i)
		caches = append(caches, c)
	}

	if after := runtime.NumGoroutine(); after > before+2 {
		t.Fatalf("goroutines grew from %d to %d after creating 100 caches", before, after)
	}
	runtime.KeepAlive(caches)
}
