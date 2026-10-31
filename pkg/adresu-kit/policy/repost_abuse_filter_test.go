package policy

import (
	"context"
	"sync"
	"testing"
	"time"

	"fiatjaf.com/nostr"

	"github.com/lessucettes/adresu-plugin/pkg/adresu-kit/config"
)

func newRepostAbuseFilter(t *testing.T) *RepostAbuseFilter {
	t.Helper()
	filter, err := NewRepostAbuseFilter(&config.RepostAbuseFilterConfig{
		Enabled:       true,
		MaxRatio:      0.2,
		MinEvents:     5,
		CacheSize:     100,
		CacheTTL:      time.Minute,
		ResetDuration: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	return filter
}

func repostMatch(t *testing.T, filter *RepostAbuseFilter, kind nostr.Kind) bool {
	t.Helper()
	res, err := filter.Match(context.Background(), &nostr.Event{Kind: kind, PubKey: fixturePubKey(1), Content: "content"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return res.Allowed
}

func TestRepostAbuseRejectsAtRatioLimit(t *testing.T) {
	filter := newRepostAbuseFilter(t)

	for i := 0; i < 10; i++ {
		if !repostMatch(t, filter, nostr.KindTextNote) {
			t.Fatalf("original post %d was rejected", i+1)
		}
	}

	// 2/12 = 16.7% is below the 20% limit, 3/13 = 23.1% reaches it.
	if !repostMatch(t, filter, nostr.KindRepost) {
		t.Fatal("first repost was rejected")
	}
	if !repostMatch(t, filter, nostr.KindRepost) {
		t.Fatal("second repost was rejected")
	}
	if repostMatch(t, filter, nostr.KindRepost) {
		t.Fatal("repost above the ratio limit was allowed")
	}
}

// Every decision must be made against the counters it then updates; otherwise
// concurrent reposts can all pass the same stale snapshot.
func TestRepostAbuseConcurrentRepostsRespectRatio(t *testing.T) {
	filter := newRepostAbuseFilter(t)

	for i := 0; i < 10; i++ {
		if !repostMatch(t, filter, nostr.KindTextNote) {
			t.Fatalf("original post %d was rejected", i+1)
		}
	}

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		accepted int
	)
	start := make(chan struct{})
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if repostMatch(t, filter, nostr.KindRepost) {
				mu.Lock()
				accepted++
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()

	if accepted > 2 {
		t.Fatalf("%d concurrent reposts were accepted, the ratio limit allows 2", accepted)
	}
}
