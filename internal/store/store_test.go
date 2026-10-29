package store

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/lessucettes/adresu-plugin/internal/config"
)

func newTestStore(t *testing.T) *BadgerStore {
	t.Helper()

	s, err := NewBadgerStore(&config.DBConfig{Path: t.TempDir()})
	if err != nil {
		t.Fatalf("NewBadgerStore: %v", err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return s
}

func keyExpiry(t *testing.T, s *BadgerStore, key string) uint64 {
	t.Helper()

	var expiresAt uint64
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(key))
		if err == nil {
			expiresAt = item.ExpiresAt()
		}
		return err
	})
	if err != nil {
		t.Fatalf("read %q: %v", key, err)
	}
	return expiresAt
}

func TestBanAuthorNormalizesPubkeyCase(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	upper := strings.Repeat("AB", 32)
	if err := s.BanAuthor(ctx, upper, time.Hour); err != nil {
		t.Fatalf("BanAuthor: %v", err)
	}

	banned, err := s.IsAuthorBanned(ctx, strings.ToLower(upper))
	if err != nil {
		t.Fatalf("IsAuthorBanned: %v", err)
	}
	if !banned {
		t.Fatal("ban stored with uppercase pubkey is not visible for the canonical lowercase pubkey")
	}

	if err := s.UnbanAuthor(ctx, strings.ToLower(upper)); err != nil {
		t.Fatalf("UnbanAuthor: %v", err)
	}
	banned, err = s.IsAuthorBanned(ctx, upper)
	if err != nil {
		t.Fatalf("IsAuthorBanned after unban: %v", err)
	}
	if banned {
		t.Fatal("author is still banned after unban")
	}
}

func TestBanAuthorDoesNotShortenExistingBan(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	pubkey := strings.Repeat("ab", 32)
	expiry := func() uint64 {
		t.Helper()
		var expiresAt uint64
		if err := s.db.View(func(txn *badger.Txn) error {
			item, err := txn.Get([]byte(banPrefix + pubkey))
			if err == nil {
				expiresAt = item.ExpiresAt()
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return expiresAt
	}
	if err := s.BanAuthor(ctx, pubkey, time.Hour); err != nil {
		t.Fatal(err)
	}
	initial := expiry()
	if err := s.BanAuthor(ctx, pubkey, time.Second); err != nil {
		t.Fatal(err)
	}
	if expiry() != initial {
		t.Fatal("a short automatic ban replaced the longer existing ban")
	}
	if err := s.BanAuthor(ctx, pubkey, 2*time.Hour); err != nil {
		t.Fatal(err)
	}
	if expiry() <= initial {
		t.Fatal("a longer ban did not extend the existing one")
	}
	var wg sync.WaitGroup
	errors := make(chan error, 4)
	start := make(chan struct{})
	minimumExpiry := uint64(time.Now().Add(6 * time.Hour).Unix())
	for _, duration := range []time.Duration{time.Second, 2 * time.Hour, 3 * time.Hour, 6 * time.Hour} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errors <- s.BanAuthor(ctx, pubkey, duration)
		}()
	}
	close(start)
	wg.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	if expiry() < minimumExpiry {
		t.Fatal("concurrent shorter bans overwrote the longest ban")
	}
}

func TestBanAuthorKeepsSubSecondBanActive(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Badger stores expiries as whole seconds. A positive duration shorter than
	// the rest of the current second must not produce an already-expired key.
	// Keep the injected deadline ahead of Badger's real clock even if this
	// test is paused across a second boundary before inspecting the entry.
	fixed := time.Now().Add(time.Hour).Truncate(time.Second)
	s.now = func() time.Time { return fixed }
	pubkey := strings.Repeat("ac", 32)
	if err := s.BanAuthor(ctx, pubkey, time.Nanosecond); err != nil {
		t.Fatalf("BanAuthor: %v", err)
	}
	banned, err := s.IsAuthorBanned(ctx, pubkey)
	if err != nil {
		t.Fatalf("IsAuthorBanned: %v", err)
	}
	if !banned {
		t.Fatal("a positive sub-second ban expired before it could be observed")
	}
	if got, want := keyExpiry(t, s, banPrefix+pubkey), uint64(fixed.Unix())+1; got != want {
		t.Fatalf("sub-second ban expiry = %d, want %d", got, want)
	}
}

func TestBanAuthorDoesNotTruncateRequestedDuration(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	fixed := time.Now().Add(time.Hour).Truncate(time.Second)
	s.now = func() time.Time { return fixed }
	pubkey := strings.Repeat("bd", 32)
	if err := s.BanAuthor(ctx, pubkey, 1500*time.Millisecond); err != nil {
		t.Fatalf("BanAuthor: %v", err)
	}

	// Badger's native WithTTL truncates 1.5 seconds to one second. The store
	// must round up instead so the configured ban is never shortened.
	if got, want := keyExpiry(t, s, banPrefix+pubkey), uint64(fixed.Unix())+2; got != want {
		t.Fatalf("ban expiry = %d, want %d", got, want)
	}
}

func TestStoreHonorsCanceledContext(t *testing.T) {
	s := newTestStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	pubkey := strings.Repeat("ef", 32)
	if err := s.BanAuthor(ctx, pubkey, time.Hour); err == nil {
		t.Fatal("BanAuthor ignored a canceled context")
	}
	if _, err := s.IsAuthorBanned(ctx, pubkey); err == nil {
		t.Fatal("IsAuthorBanned ignored a canceled context")
	}
	if err := s.UnbanAuthor(ctx, pubkey); err == nil {
		t.Fatal("UnbanAuthor ignored a canceled context")
	}
}

func TestApplyModerationPersistsReplaySuppressionAcrossReopen(t *testing.T) {
	dbPath := t.TempDir()
	ctx := context.Background()
	pubkey := strings.Repeat("aa", 32)
	banAction := strings.Repeat("1", 64)
	unbanAction := strings.Repeat("2", 64)

	s, err := NewBadgerStore(&config.DBConfig{Path: dbPath})
	if err != nil {
		t.Fatalf("NewBadgerStore: %v", err)
	}
	fixed := time.Now().Truncate(time.Second)
	s.now = func() time.Time { return fixed }

	applied, err := s.ApplyModeration(ctx, banAction, strings.ToUpper(pubkey), time.Hour)
	if err != nil {
		t.Fatalf("ApplyModeration ban: %v", err)
	}
	if !applied {
		t.Fatal("first moderation action was not applied")
	}
	initialExpiry := keyExpiry(t, s, banPrefix+pubkey)
	if markerExpiry := keyExpiry(t, s, moderationActionPrefix+banAction); markerExpiry != 0 {
		t.Fatalf("moderation marker expiry = %d, want no TTL", markerExpiry)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s, err = NewBadgerStore(&config.DBConfig{Path: dbPath})
	if err != nil {
		t.Fatalf("reopen NewBadgerStore: %v", err)
	}
	defer func() {
		if err := s.Close(); err != nil {
			t.Fatalf("Close reopened store: %v", err)
		}
	}()

	// A replay must neither reapply the ban nor extend it, even though the
	// requested duration is now longer and the process restarted.
	applied, err = s.ApplyModeration(ctx, banAction, pubkey, 2*time.Hour)
	if err != nil {
		t.Fatalf("ApplyModeration replay: %v", err)
	}
	if applied {
		t.Fatal("replayed moderation action was applied after store reopen")
	}
	if got := keyExpiry(t, s, banPrefix+pubkey); got != initialExpiry {
		t.Fatalf("replay changed ban expiry: got %d, want %d", got, initialExpiry)
	}
	if expiry := keyExpiry(t, s, moderationActionPrefix+banAction); expiry != 0 {
		t.Fatalf("reopened moderation marker expiry = %d, want no TTL", expiry)
	}

	applied, err = s.ApplyModeration(ctx, unbanAction, pubkey, 0)
	if err != nil {
		t.Fatalf("ApplyModeration unban: %v", err)
	}
	if !applied {
		t.Fatal("distinct moderation unban was not applied")
	}
	banned, err := s.IsAuthorBanned(ctx, pubkey)
	if err != nil {
		t.Fatalf("IsAuthorBanned: %v", err)
	}
	if banned {
		t.Fatal("unban did not clear the ban")
	}

	// The old ban action remains suppressed after the later unban.
	applied, err = s.ApplyModeration(ctx, banAction, pubkey, time.Hour)
	if err != nil {
		t.Fatalf("ApplyModeration stale replay: %v", err)
	}
	if applied {
		t.Fatal("stale ban replay was applied after the unban")
	}
	banned, err = s.IsAuthorBanned(ctx, pubkey)
	if err != nil {
		t.Fatalf("IsAuthorBanned after stale replay: %v", err)
	}
	if banned {
		t.Fatal("stale ban replay re-banned the author after the unban")
	}
}

func TestApplyModerationRejectsNegativeDurationWithoutConsumingAction(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	pubkey := strings.Repeat("ab", 32)
	action := strings.Repeat("3", 64)

	applied, err := s.ApplyModeration(ctx, action, pubkey, -time.Second)
	if err == nil {
		t.Fatal("negative moderation duration was accepted")
	}
	if applied {
		t.Fatal("negative moderation duration reported an applied action")
	}

	// The rejected call must not leave a marker behind.
	applied, err = s.ApplyModeration(ctx, action, pubkey, time.Hour)
	if err != nil {
		t.Fatalf("ApplyModeration after rejection: %v", err)
	}
	if !applied {
		t.Fatal("negative duration consumed the moderation action")
	}
	banned, err := s.IsAuthorBanned(ctx, pubkey)
	if err != nil {
		t.Fatalf("IsAuthorBanned: %v", err)
	}
	if !banned {
		t.Fatal("retried moderation action did not apply the ban")
	}
}

func TestApplyModerationDoesNotShortenExistingBan(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	pubkey := strings.Repeat("ba", 32)
	fixed := time.Now().Truncate(time.Second)
	s.now = func() time.Time { return fixed }

	if err := s.BanAuthor(ctx, pubkey, 2*time.Hour); err != nil {
		t.Fatalf("BanAuthor: %v", err)
	}
	initialExpiry := keyExpiry(t, s, banPrefix+pubkey)

	applied, err := s.ApplyModeration(ctx, strings.Repeat("4", 64), pubkey, time.Hour)
	if err != nil {
		t.Fatalf("ApplyModeration shorter ban: %v", err)
	}
	if !applied {
		t.Fatal("moderation action was not marked although it was processed")
	}
	if got := keyExpiry(t, s, banPrefix+pubkey); got != initialExpiry {
		t.Fatalf("shorter moderation ban changed expiry: got %d, want %d", got, initialExpiry)
	}

	applied, err = s.ApplyModeration(ctx, strings.Repeat("5", 64), pubkey, 3*time.Hour)
	if err != nil {
		t.Fatalf("ApplyModeration longer ban: %v", err)
	}
	if !applied {
		t.Fatal("distinct longer moderation action was not applied")
	}
	if got, want := keyExpiry(t, s, banPrefix+pubkey), uint64(fixed.Add(3*time.Hour).Unix()); got != want {
		t.Fatalf("longer moderation ban expiry = %d, want %d", got, want)
	}
}

func TestApplyModerationRetriesAfterCanceledContext(t *testing.T) {
	s := newTestStore(t)
	pubkey := strings.Repeat("bb", 32)
	action := strings.Repeat("6", 64)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	applied, err := s.ApplyModeration(ctx, action, pubkey, time.Hour)
	if err == nil {
		t.Fatal("ApplyModeration ignored a canceled context")
	}
	if applied {
		t.Fatal("canceled ApplyModeration reported success")
	}
	banned, err := s.IsAuthorBanned(context.Background(), pubkey)
	if err != nil {
		t.Fatalf("IsAuthorBanned: %v", err)
	}
	if banned {
		t.Fatal("canceled transaction applied a partial ban")
	}

	applied, err = s.ApplyModeration(context.Background(), action, pubkey, time.Hour)
	if err != nil {
		t.Fatalf("ApplyModeration retry: %v", err)
	}
	if !applied {
		t.Fatal("failed transaction consumed the moderation action")
	}
	banned, err = s.IsAuthorBanned(context.Background(), pubkey)
	if err != nil {
		t.Fatalf("IsAuthorBanned after retry: %v", err)
	}
	if !banned {
		t.Fatal("retry after a failed transaction did not apply the ban")
	}
}
