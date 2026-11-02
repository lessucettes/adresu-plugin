package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"fiatjaf.com/nostr"
	"github.com/dgraph-io/badger/v4"

	"github.com/lessucettes/adresu-plugin/pkg/adresu-kit/reputation"
)

func readFollowTestRaw(t *testing.T, s *BadgerStore, key []byte) ([]byte, uint64, bool) {
	t.Helper()
	var value []byte
	var version uint64
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get(key)
		if err != nil {
			return err
		}
		version = item.Version()
		value, err = item.ValueCopy(nil)
		return err
	})
	if err != nil {
		if errors.Is(err, badger.ErrKeyNotFound) {
			return nil, 0, false
		}
		t.Fatalf("read raw follow value %q: %v", key, err)
	}
	return value, version, true
}

func writeFollowTestRaw(t *testing.T, s *BadgerStore, key, value []byte) {
	t.Helper()
	if err := s.db.Update(func(txn *badger.Txn) error {
		return txn.Set(key, value)
	}); err != nil {
		t.Fatalf("write raw follow value %q: %v", key, err)
	}
}

func deleteFollowTestRaw(t *testing.T, s *BadgerStore, key []byte) {
	t.Helper()
	if err := s.db.Update(func(txn *badger.Txn) error {
		return txn.Delete(key)
	}); err != nil {
		t.Fatalf("delete raw follow value %q: %v", key, err)
	}
}

func followTestList(author nostr.PubKey, eventSeed byte, createdAt nostr.Timestamp, fetched time.Time) reputation.FollowList {
	return reputation.FollowList{
		Author:    author,
		EventID:   reputationTestEventID(eventSeed),
		CreatedAt: createdAt,
		FetchedAt: fetched,
		Follows:   []nostr.PubKey{reputationTestPubKey(0x01), reputationTestPubKey(0x02)},
	}
}

func assertFollowTestBodyUnchanged(t *testing.T, before []byte, beforeVersion uint64, after []byte, afterVersion uint64) {
	t.Helper()
	if !bytes.Equal(before, after) {
		t.Fatal("same-author follow body bytes changed")
	}
	if beforeVersion != afterVersion {
		t.Fatalf("follow body item version changed from %d to %d", beforeVersion, afterVersion)
	}
}

func TestFollowListSameVersionRefreshKeepsBodyBytes(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	author := reputationTestPubKey(0xc1)
	fetched := time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC)

	base := followTestList(author, 0x20, 100, fetched)
	if err := s.SaveFollowList(ctx, base); err != nil {
		t.Fatalf("SaveFollowList(base): %v", err)
	}
	bodyBefore, bodyVersionBefore, found := readFollowTestRaw(t, s, followListKey(author))
	if !found {
		t.Fatal("body missing after save")
	}
	receiptBefore, _, found := readFollowTestRaw(t, s, followReceiptKey(author))
	if !found {
		t.Fatal("receipt missing after save")
	}

	// Same signed event, later observation, and deliberately different
	// follows: the signed content must remain untouched.
	refresh := base
	refresh.FetchedAt = fetched.Add(time.Hour)
	refresh.Follows = []nostr.PubKey{reputationTestPubKey(0x09)}
	if err := s.SaveFollowList(ctx, refresh); err != nil {
		t.Fatalf("SaveFollowList(refresh): %v", err)
	}

	bodyAfter, bodyVersionAfter, _ := readFollowTestRaw(t, s, followListKey(author))
	assertFollowTestBodyUnchanged(t, bodyBefore, bodyVersionBefore, bodyAfter, bodyVersionAfter)
	receiptAfter, _, _ := readFollowTestRaw(t, s, followReceiptKey(author))
	if bytes.Equal(receiptBefore, receiptAfter) {
		t.Fatal("same-version refresh did not update the receipt header")
	}

	got := loadReputationTestFollowList(t, s, author)
	if !got.FetchedAt.Equal(refresh.FetchedAt) {
		t.Fatalf("effective fetched_at = %v, want %v", got.FetchedAt, refresh.FetchedAt)
	}
	if len(got.Follows) != len(base.Follows) || got.Follows[0] != base.Follows[0] || got.Follows[1] != base.Follows[1] {
		t.Fatalf("same-version refresh changed signed content: %+v", got.Follows)
	}
}

func TestFollowListReceiptKeyIsOutsideLegacyBodyPrefix(t *testing.T) {
	author := reputationTestPubKey(0xc2)
	bodyPrefix := []byte(reputationFollowPrefix)
	if bytes.HasPrefix(followReceiptKey(author), bodyPrefix) {
		t.Fatalf("receipt key %q is visible to a legacy body-prefix scan", followReceiptKey(author))
	}

	s := newTestStore(t)
	list := followTestList(author, 0x21, 101, time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC))
	if err := s.SaveFollowList(context.Background(), list); err != nil {
		t.Fatalf("SaveFollowList: %v", err)
	}

	var keys [][]byte
	if err := s.db.View(func(txn *badger.Txn) error {
		options := badger.DefaultIteratorOptions
		options.PrefetchValues = false
		iterator := txn.NewIterator(options)
		defer iterator.Close()
		for iterator.Seek(bodyPrefix); iterator.ValidForPrefix(bodyPrefix); iterator.Next() {
			keys = append(keys, iterator.Item().KeyCopy(nil))
		}
		return nil
	}); err != nil {
		t.Fatalf("scan follow body prefix: %v", err)
	}
	if len(keys) != 1 || !bytes.Equal(keys[0], followListKey(author)) {
		t.Fatalf("legacy body-prefix scan returned %q, want only %q", keys, followListKey(author))
	}
}

func TestFollowListLegacyRowWithoutReceipt(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	author := reputationTestPubKey(0xc3)
	fetched := time.Date(2026, 6, 7, 8, 9, 10, 0, time.UTC)
	list := followTestList(author, 0x22, 102, fetched)

	// Simulate a row written before receipts existed: body only.
	body, err := encodeFollowList(list)
	if err != nil {
		t.Fatalf("encode legacy body: %v", err)
	}
	writeFollowTestRaw(t, s, followListKey(author), body)
	if _, _, found := readFollowTestRaw(t, s, followReceiptKey(author)); found {
		t.Fatal("legacy fixture unexpectedly has a receipt")
	}

	got := loadReputationTestFollowList(t, s, author)
	if !got.FetchedAt.Equal(fetched) {
		t.Fatalf("legacy load fetched_at = %v, want %v", got.FetchedAt, fetched)
	}

	// A stale same-version observation must not roll FetchedAt back, but it
	// lazily creates the receipt from the body's own version/time.
	stale := list
	stale.FetchedAt = fetched.Add(-time.Hour)
	if err := s.SaveFollowList(ctx, stale); err != nil {
		t.Fatalf("SaveFollowList(legacy stale refresh): %v", err)
	}
	got = loadReputationTestFollowList(t, s, author)
	if !got.FetchedAt.Equal(fetched) {
		t.Fatalf("legacy stale refresh moved fetched_at to %v, want %v", got.FetchedAt, fetched)
	}
	receiptValue, _, found := readFollowTestRaw(t, s, followReceiptKey(author))
	if !found {
		t.Fatal("legacy refresh did not create a receipt")
	}
	receipt, err := decodeFollowReceipt(followReceiptKey(author), receiptValue)
	if err != nil {
		t.Fatalf("decode lazily created receipt: %v", err)
	}
	if receipt.EventID != list.EventID || receipt.CreatedAt != list.CreatedAt || !receipt.FetchedAt.Equal(fetched) {
		t.Fatalf("lazily created receipt = %+v, want version %s/%d at %v", receipt, list.EventID.Hex(), list.CreatedAt, fetched)
	}

	bodyBefore, versionBefore, _ := readFollowTestRaw(t, s, followListKey(author))
	forward := list
	forward.FetchedAt = fetched.Add(time.Hour)
	if err := s.SaveFollowList(ctx, forward); err != nil {
		t.Fatalf("SaveFollowList(legacy forward refresh): %v", err)
	}
	bodyAfter, versionAfter, _ := readFollowTestRaw(t, s, followListKey(author))
	assertFollowTestBodyUnchanged(t, bodyBefore, versionBefore, bodyAfter, versionAfter)
	if got := loadReputationTestFollowList(t, s, author); !got.FetchedAt.Equal(forward.FetchedAt) {
		t.Fatalf("legacy forward refresh fetched_at = %v, want %v", got.FetchedAt, forward.FetchedAt)
	}
}

func TestFollowListOldVersionCannotRefreshReceipt(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	author := reputationTestPubKey(0xc4)
	fetched := time.Date(2026, 7, 8, 9, 10, 11, 0, time.UTC)

	newer := followTestList(author, 0x20, 200, fetched)
	if err := s.SaveFollowList(ctx, newer); err != nil {
		t.Fatalf("SaveFollowList(newer): %v", err)
	}
	bodyBefore, versionBefore, _ := readFollowTestRaw(t, s, followListKey(author))

	older := followTestList(author, 0x10, 199, fetched.Add(3*time.Hour))
	if err := s.SaveFollowList(ctx, older); err != nil {
		t.Fatalf("SaveFollowList(older): %v", err)
	}
	got := loadReputationTestFollowList(t, s, author)
	if got.EventID != newer.EventID || !got.FetchedAt.Equal(fetched) {
		t.Fatalf("older event refreshed receipt: event %s fetched_at %v", got.EventID.Hex(), got.FetchedAt)
	}

	largerTie := followTestList(author, 0x30, newer.CreatedAt, fetched.Add(4*time.Hour))
	if err := s.SaveFollowList(ctx, largerTie); err != nil {
		t.Fatalf("SaveFollowList(larger tie): %v", err)
	}
	got = loadReputationTestFollowList(t, s, author)
	if got.EventID != newer.EventID || !got.FetchedAt.Equal(fetched) {
		t.Fatalf("losing tie refreshed receipt: event %s fetched_at %v", got.EventID.Hex(), got.FetchedAt)
	}

	bodyAfter, versionAfter, _ := readFollowTestRaw(t, s, followListKey(author))
	assertFollowTestBodyUnchanged(t, bodyBefore, versionBefore, bodyAfter, versionAfter)

	// The stored version itself may still advance its observation time.
	same := newer
	same.FetchedAt = fetched.Add(5 * time.Hour)
	if err := s.SaveFollowList(ctx, same); err != nil {
		t.Fatalf("SaveFollowList(same version): %v", err)
	}
	got = loadReputationTestFollowList(t, s, author)
	if !got.FetchedAt.Equal(same.FetchedAt) {
		t.Fatalf("stored version fetched_at = %v, want %v", got.FetchedAt, same.FetchedAt)
	}
}

func TestFollowListRejectsReceiptMismatch(t *testing.T) {
	ctx := context.Background()
	author := reputationTestPubKey(0xc5)
	fetched := time.Date(2026, 8, 9, 10, 11, 12, 0, time.UTC)
	list := followTestList(author, 0x23, 103, fetched)

	mutateReceipt := func(t *testing.T, s *BadgerStore, mutate func(*followReceiptRecord)) {
		t.Helper()
		value, _, found := readFollowTestRaw(t, s, followReceiptKey(author))
		if !found {
			t.Fatal("receipt missing")
		}
		var record followReceiptRecord
		if err := json.Unmarshal(value, &record); err != nil {
			t.Fatalf("decode receipt fixture: %v", err)
		}
		mutate(&record)
		encoded, err := json.Marshal(record)
		if err != nil {
			t.Fatalf("encode receipt fixture: %v", err)
		}
		writeFollowTestRaw(t, s, followReceiptKey(author), encoded)
	}

	t.Run("created_at mismatch", func(t *testing.T) {
		s := newTestStore(t)
		if err := s.SaveFollowList(ctx, list); err != nil {
			t.Fatalf("SaveFollowList: %v", err)
		}
		mutateReceipt(t, s, func(record *followReceiptRecord) { record.CreatedAt++ })
		if _, err := s.LoadFollowList(ctx, author); err == nil {
			t.Fatal("LoadFollowList accepted a receipt with a different created_at")
		}
	})

	t.Run("event id mismatch", func(t *testing.T) {
		s := newTestStore(t)
		if err := s.SaveFollowList(ctx, list); err != nil {
			t.Fatalf("SaveFollowList: %v", err)
		}
		mutateReceipt(t, s, func(record *followReceiptRecord) {
			record.EventID = reputationTestEventID(0x99).Hex()
		})
		if _, err := s.LoadFollowList(ctx, author); err == nil {
			t.Fatal("LoadFollowList accepted a receipt with a different event ID")
		}
	})

	t.Run("zero fetched_at", func(t *testing.T) {
		s := newTestStore(t)
		if err := s.SaveFollowList(ctx, list); err != nil {
			t.Fatalf("SaveFollowList: %v", err)
		}
		mutateReceipt(t, s, func(record *followReceiptRecord) { record.FetchedAt = time.Time{} })
		if _, err := s.LoadFollowList(ctx, author); err == nil {
			t.Fatal("LoadFollowList accepted a receipt with zero fetched_at")
		}
	})

	t.Run("malformed receipt", func(t *testing.T) {
		s := newTestStore(t)
		if err := s.SaveFollowList(ctx, list); err != nil {
			t.Fatalf("SaveFollowList: %v", err)
		}
		writeFollowTestRaw(t, s, followReceiptKey(author), []byte("{not-json"))
		if _, err := s.LoadFollowList(ctx, author); err == nil {
			t.Fatal("LoadFollowList accepted a malformed receipt")
		}
	})

	t.Run("oversized receipt", func(t *testing.T) {
		s := newTestStore(t)
		if err := s.SaveFollowList(ctx, list); err != nil {
			t.Fatalf("SaveFollowList: %v", err)
		}
		writeFollowTestRaw(t, s, followReceiptKey(author), bytes.Repeat([]byte{'x'}, maxFollowReceiptBytes+1))
		if _, err := s.LoadFollowList(ctx, author); err == nil {
			t.Fatal("LoadFollowList decoded an oversized receipt")
		}
	})

	t.Run("receipt without body", func(t *testing.T) {
		s := newTestStore(t)
		if err := s.SaveFollowList(ctx, list); err != nil {
			t.Fatalf("SaveFollowList: %v", err)
		}
		deleteFollowTestRaw(t, s, followListKey(author))
		if _, err := s.LoadFollowList(ctx, author); err == nil {
			t.Fatal("LoadFollowList accepted a receipt without a body")
		}
	})
}
