package store

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"fiatjaf.com/nostr"

	"github.com/lessucettes/adresu-plugin/pkg/adresu-kit/reputation"
)

func reputationTestPubKey(seed byte) nostr.PubKey {
	var pubkey nostr.PubKey
	for i := range pubkey {
		pubkey[i] = seed
	}
	return pubkey
}

func reputationTestEventID(seed byte) nostr.ID {
	var eventID nostr.ID
	for i := range eventID {
		eventID[i] = seed
	}
	return eventID
}

func loadReputationTestFollowList(t *testing.T, s *BadgerStore, author nostr.PubKey) *reputation.FollowList {
	t.Helper()
	list, err := s.LoadFollowList(context.Background(), author)
	if err != nil {
		t.Fatalf("LoadFollowList(%s): %v", author.Hex(), err)
	}
	if list == nil {
		t.Fatalf("LoadFollowList(%s) returned no list", author.Hex())
	}
	return list
}

func TestFollowListRoundTripAndPerAuthorLoad(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	fetched := time.Now().UTC().Truncate(time.Microsecond)

	alice := reputationTestPubKey(0x11)
	bob := reputationTestPubKey(0x22)
	aliceList := reputation.FollowList{
		Author:    alice,
		EventID:   reputationTestEventID(0x31),
		CreatedAt: 1_700_000_000,
		FetchedAt: fetched,
		Follows:   []nostr.PubKey{reputationTestPubKey(0x33), reputationTestPubKey(0x44)},
	}
	bobList := reputation.FollowList{
		Author:    bob,
		EventID:   reputationTestEventID(0x32),
		CreatedAt: 1_700_000_100,
		FetchedAt: fetched.Add(time.Minute),
		Follows:   []nostr.PubKey{},
	}
	for _, list := range []reputation.FollowList{aliceList, bobList} {
		if err := s.SaveFollowList(ctx, list); err != nil {
			t.Fatalf("SaveFollowList(%s): %v", list.Author.Hex(), err)
		}
	}

	gotAlice := loadReputationTestFollowList(t, s, alice)
	if gotAlice.Author != aliceList.Author ||
		gotAlice.EventID != aliceList.EventID ||
		gotAlice.CreatedAt != aliceList.CreatedAt ||
		!gotAlice.FetchedAt.Equal(aliceList.FetchedAt) ||
		len(gotAlice.Follows) != len(aliceList.Follows) {
		t.Fatalf("round-tripped follow list = %+v, want %+v", *gotAlice, aliceList)
	}
	for i := range aliceList.Follows {
		if gotAlice.Follows[i] != aliceList.Follows[i] {
			t.Fatalf("follow %d = %s, want %s", i, gotAlice.Follows[i].Hex(), aliceList.Follows[i].Hex())
		}
	}

	gotBob := loadReputationTestFollowList(t, s, bob)
	if gotBob.Follows == nil {
		t.Fatal("authored empty follow list decoded as nil, losing the difference from absence")
	}
	if len(gotBob.Follows) != 0 {
		t.Fatalf("empty follow list has %d entries", len(gotBob.Follows))
	}

	missing := reputationTestPubKey(0x55)
	absent, err := s.LoadFollowList(ctx, missing)
	if err != nil {
		t.Fatalf("LoadFollowList(absent): %v", err)
	}
	if absent != nil {
		t.Fatalf("LoadFollowList(absent) = %+v, want nil", *absent)
	}

	// Loading one author must never return another author's list.
	if got := loadReputationTestFollowList(t, s, bob); got.EventID != bobList.EventID {
		t.Fatalf("per-author load returned event %s, want %s", got.EventID.Hex(), bobList.EventID.Hex())
	}
	if got := loadReputationTestFollowList(t, s, alice); got.EventID != aliceList.EventID {
		t.Fatalf("per-author load returned event %s, want %s", got.EventID.Hex(), aliceList.EventID.Hex())
	}
}

func TestSaveFollowListTieBreakAndFetchedAtRefresh(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	author := reputationTestPubKey(0x66)
	fetched := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	base := reputation.FollowList{
		Author:    author,
		EventID:   reputationTestEventID(0x20),
		CreatedAt: 100,
		FetchedAt: fetched,
		Follows:   []nostr.PubKey{reputationTestPubKey(0x01), reputationTestPubKey(0x02)},
	}
	if err := s.SaveFollowList(ctx, base); err != nil {
		t.Fatalf("SaveFollowList(base): %v", err)
	}

	// An older signed event must not roll storage back, even if fetched later.
	older := reputation.FollowList{
		Author:    author,
		EventID:   reputationTestEventID(0x10),
		CreatedAt: 99,
		FetchedAt: fetched.Add(time.Hour),
		Follows:   []nostr.PubKey{reputationTestPubKey(0x03)},
	}
	if err := s.SaveFollowList(ctx, older); err != nil {
		t.Fatalf("SaveFollowList(older): %v", err)
	}
	if got := loadReputationTestFollowList(t, s, author); got.EventID != base.EventID || got.CreatedAt != base.CreatedAt {
		t.Fatalf("older event replaced newer: got event %s at %d", got.EventID.Hex(), got.CreatedAt)
	}

	// At an equal timestamp, the larger event ID loses.
	larger := reputation.FollowList{
		Author:    author,
		EventID:   reputationTestEventID(0x30),
		CreatedAt: base.CreatedAt,
		FetchedAt: fetched.Add(2 * time.Hour),
		Follows:   []nostr.PubKey{reputationTestPubKey(0x04)},
	}
	if err := s.SaveFollowList(ctx, larger); err != nil {
		t.Fatalf("SaveFollowList(larger): %v", err)
	}
	if got := loadReputationTestFollowList(t, s, author); got.EventID != base.EventID {
		t.Fatalf("equal-time larger ID replaced %s", got.EventID.Hex())
	}

	// At an equal timestamp, the smaller event ID wins.
	lower := reputation.FollowList{
		Author:    author,
		EventID:   reputationTestEventID(0x10),
		CreatedAt: base.CreatedAt,
		FetchedAt: fetched,
		Follows:   []nostr.PubKey{reputationTestPubKey(0x05), reputationTestPubKey(0x06)},
	}
	if err := s.SaveFollowList(ctx, lower); err != nil {
		t.Fatalf("SaveFollowList(lower): %v", err)
	}
	if got := loadReputationTestFollowList(t, s, author); got.EventID != lower.EventID || len(got.Follows) != 2 {
		t.Fatalf("equal-time lower ID did not replace: %+v", *got)
	}

	// The previous winner must not come back later.
	if err := s.SaveFollowList(ctx, base); err != nil {
		t.Fatalf("SaveFollowList(old winner): %v", err)
	}
	if got := loadReputationTestFollowList(t, s, author); got.EventID != lower.EventID {
		t.Fatalf("old same-time event rolled storage back to %s", got.EventID.Hex())
	}

	// The same signed event may forward FetchedAt, but content is immutable.
	same := lower
	same.FetchedAt = fetched.Add(-time.Hour)
	same.Follows = []nostr.PubKey{reputationTestPubKey(0x07)}
	if err := s.SaveFollowList(ctx, same); err != nil {
		t.Fatalf("SaveFollowList(stale refresh): %v", err)
	}
	if got := loadReputationTestFollowList(t, s, author); !got.FetchedAt.Equal(fetched) || len(got.Follows) != 2 {
		t.Fatalf("stale same-version refresh changed %+v", *got)
	}

	same.FetchedAt = fetched.Add(time.Hour)
	if err := s.SaveFollowList(ctx, same); err != nil {
		t.Fatalf("SaveFollowList(refresh): %v", err)
	}
	got := loadReputationTestFollowList(t, s, author)
	if !got.FetchedAt.Equal(same.FetchedAt) {
		t.Fatalf("fetched_at = %v, want %v", got.FetchedAt, same.FetchedAt)
	}
	if len(got.Follows) != 2 || got.Follows[0] != lower.Follows[0] || got.Follows[1] != lower.Follows[1] {
		t.Fatalf("same-version refresh changed signed content: %+v", got.Follows)
	}
}

func TestSaveFollowListEmptyReplacesPrevious(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	author := reputationTestPubKey(0x77)
	now := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)

	nonEmpty := reputation.FollowList{
		Author:    author,
		EventID:   reputationTestEventID(0x20),
		CreatedAt: 100,
		FetchedAt: now,
		Follows:   []nostr.PubKey{reputationTestPubKey(0x01)},
	}
	if err := s.SaveFollowList(ctx, nonEmpty); err != nil {
		t.Fatalf("SaveFollowList(non-empty): %v", err)
	}
	empty := reputation.FollowList{
		Author:    author,
		EventID:   reputationTestEventID(0x21),
		CreatedAt: 101,
		FetchedAt: now.Add(time.Minute),
		Follows:   []nostr.PubKey{},
	}
	if err := s.SaveFollowList(ctx, empty); err != nil {
		t.Fatalf("SaveFollowList(empty): %v", err)
	}
	got := loadReputationTestFollowList(t, s, author)
	if got.CreatedAt != empty.CreatedAt || len(got.Follows) != 0 || got.Follows == nil {
		t.Fatalf("real empty list did not replace previous list: %+v", *got)
	}

	// An older non-empty event cannot resurrect the previous list.
	if err := s.SaveFollowList(ctx, nonEmpty); err != nil {
		t.Fatalf("SaveFollowList(old non-empty): %v", err)
	}
	if got := loadReputationTestFollowList(t, s, author); len(got.Follows) != 0 || got.CreatedAt != empty.CreatedAt {
		t.Fatalf("older non-empty event replaced empty list: %+v", *got)
	}
}

func TestFollowListContextAndAuthorIsolation(t *testing.T) {
	s := newTestStore(t)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	author := reputationTestPubKey(0x88)
	list := reputation.FollowList{
		Author:    author,
		EventID:   reputationTestEventID(0x01),
		CreatedAt: 10,
		FetchedAt: time.Now().UTC(),
	}
	if err := s.SaveFollowList(canceled, list); !errors.Is(err, context.Canceled) {
		t.Fatalf("SaveFollowList with canceled context error = %v, want context.Canceled", err)
	}
	if _, err := s.LoadFollowList(canceled, author); !errors.Is(err, context.Canceled) {
		t.Fatalf("LoadFollowList with canceled context error = %v, want context.Canceled", err)
	}

	ctx := context.Background()
	if got, err := s.LoadFollowList(ctx, author); err != nil || got != nil {
		t.Fatalf("canceled save left data behind: list=%v err=%v", got, err)
	}
	if err := s.SaveFollowList(ctx, list); err != nil {
		t.Fatalf("SaveFollowList: %v", err)
	}
	second := list
	second.Author = reputationTestPubKey(0x99)
	second.EventID = reputationTestEventID(0x02)
	if err := s.SaveFollowList(ctx, second); err != nil {
		t.Fatalf("SaveFollowList(second): %v", err)
	}

	got := loadReputationTestFollowList(t, s, author)
	if got.Author != author || got.EventID != list.EventID || got.CreatedAt != list.CreatedAt {
		t.Fatalf("first author load = %+v, want author %s event %s at %d", *got, author.Hex(), list.EventID.Hex(), list.CreatedAt)
	}
	gotSecond := loadReputationTestFollowList(t, s, second.Author)
	if gotSecond.Author != second.Author || gotSecond.EventID != second.EventID {
		t.Fatalf("second author load = %+v, want author %s event %s", *gotSecond, second.Author.Hex(), second.EventID.Hex())
	}
	if got.FetchedAt.Equal(gotSecond.FetchedAt) && got.EventID == gotSecond.EventID {
		t.Fatal("two authors returned the same stored list")
	}
}

func TestSaveFollowListConcurrentVersionsKeepNewest(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	author := reputationTestPubKey(0xaa)
	const writers = 12

	start := make(chan struct{})
	errs := make(chan error, writers)
	var group sync.WaitGroup
	for i := 1; i <= writers; i++ {
		group.Add(1)
		go func(version int) {
			defer group.Done()
			<-start
			errs <- s.SaveFollowList(ctx, reputation.FollowList{
				Author:    author,
				EventID:   reputationTestEventID(byte(version)),
				CreatedAt: nostr.Timestamp(version),
				FetchedAt: time.Now().UTC(),
				Follows:   []nostr.PubKey{reputationTestPubKey(byte(version))},
			})
		}(i)
	}
	close(start)
	group.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent SaveFollowList: %v", err)
		}
	}
	got := loadReputationTestFollowList(t, s, author)
	if got.CreatedAt != nostr.Timestamp(writers) {
		t.Fatalf("newest created_at = %d, want %d", got.CreatedAt, writers)
	}
}

func TestReputationStorageNamespaceIsolation(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	author := reputationTestPubKey(0xbb)

	list := reputation.FollowList{
		Author:    author,
		EventID:   reputationTestEventID(0x01),
		CreatedAt: 50,
		FetchedAt: time.Now().UTC(),
		Follows:   []nostr.PubKey{reputationTestPubKey(0x02)},
	}
	if err := s.SaveFollowList(ctx, list); err != nil {
		t.Fatalf("SaveFollowList: %v", err)
	}
	if err := s.BanAuthor(ctx, author.Hex(), time.Hour); err != nil {
		t.Fatalf("BanAuthor: %v", err)
	}
	snapshot := &reputation.Snapshot{
		ConfigID:     "config-isolation",
		CalculatedAt: time.Now().UTC(),
		ValidUntil:   time.Now().UTC().Add(time.Hour),
		Coverage:     1,
		Nodes:        1,
		Edges:        0,
		Scores:       map[nostr.PubKey]reputation.Score{author: {TrustRank: 0.5}},
	}
	if err := s.SaveReputationSnapshot(ctx, snapshot); err != nil {
		t.Fatalf("SaveReputationSnapshot: %v", err)
	}

	got := loadReputationTestFollowList(t, s, author)
	if got.EventID != list.EventID || len(got.Follows) != 1 {
		t.Fatalf("snapshot/ban maintenance modified follow list: %+v", *got)
	}
	banned, err := s.IsAuthorBanned(ctx, author.Hex())
	if err != nil {
		t.Fatalf("IsAuthorBanned: %v", err)
	}
	if !banned {
		t.Fatal("reputation snapshot save removed the ban entry")
	}
	loadedSnapshot, err := s.LoadReputationSnapshot(ctx)
	if err != nil {
		t.Fatalf("LoadReputationSnapshot: %v", err)
	}
	if loadedSnapshot == nil || loadedSnapshot.ConfigID != snapshot.ConfigID {
		t.Fatalf("follow-list save disturbed snapshot: %+v", loadedSnapshot)
	}
}
