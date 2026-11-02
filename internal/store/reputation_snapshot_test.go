package store

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"fiatjaf.com/nostr"
	"github.com/dgraph-io/badger/v4"

	"github.com/lessucettes/adresu-plugin/internal/config"
	"github.com/lessucettes/adresu-plugin/pkg/adresu-kit/reputation"
)

func snapshotTestPubKey(index int) nostr.PubKey {
	return nostr.PubKey(sha256.Sum256([]byte(fmt.Sprintf("snapshot-pubkey-%d", index))))
}

func reputationTestSnapshot(scoreCount int, configID string) *reputation.Snapshot {
	scores := make(map[nostr.PubKey]reputation.Score, scoreCount)
	for i := 0; i < scoreCount; i++ {
		scores[snapshotTestPubKey(i)] = reputation.Score{
			PageRank:  float64(i+1) / float64(scoreCount+1),
			TrustRank: float64(scoreCount-i) / float64(scoreCount+1),
		}
	}
	return &reputation.Snapshot{
		ConfigID:     configID,
		CalculatedAt: time.Date(2026, 3, 4, 5, 6, 7, 123456789, time.UTC),
		ValidUntil:   time.Date(2026, 3, 5, 5, 6, 7, 123456789, time.UTC),
		Coverage:     0.75,
		Nodes:        scoreCount,
		Edges:        scoreCount * 2,
		Scores:       scores,
	}
}

func assertReputationSnapshotEqual(t *testing.T, want, got *reputation.Snapshot) {
	t.Helper()
	if got == nil {
		t.Fatal("LoadReputationSnapshot returned nil")
	}
	if got.ConfigID != want.ConfigID {
		t.Fatalf("config ID = %q, want %q", got.ConfigID, want.ConfigID)
	}
	if !got.CalculatedAt.Equal(want.CalculatedAt) {
		t.Fatalf("calculated_at = %v, want %v", got.CalculatedAt, want.CalculatedAt)
	}
	if !got.ValidUntil.Equal(want.ValidUntil) {
		t.Fatalf("valid_until = %v, want %v", got.ValidUntil, want.ValidUntil)
	}
	if got.Coverage != want.Coverage || got.Nodes != want.Nodes || got.Edges != want.Edges {
		t.Fatalf("metadata = coverage %v nodes %d edges %d, want %v/%d/%d",
			got.Coverage, got.Nodes, got.Edges, want.Coverage, want.Nodes, want.Edges)
	}
	if len(got.Scores) != len(want.Scores) {
		t.Fatalf("score count = %d, want %d", len(got.Scores), len(want.Scores))
	}
	for pubkey, wantScore := range want.Scores {
		gotScore, ok := got.Scores[pubkey]
		if !ok {
			t.Fatalf("missing score for %s", pubkey.Hex())
		}
		if gotScore != wantScore {
			t.Fatalf("score for %s = %+v, want %+v", pubkey.Hex(), gotScore, wantScore)
		}
	}
}

func readReputationTestSnapshotManifest(t *testing.T, s *BadgerStore) snapshotManifest {
	t.Helper()
	var manifest snapshotManifest
	err := s.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(reputationSnapshotManifestKey))
		if err != nil {
			return err
		}
		value, err := item.ValueCopy(nil)
		if err != nil {
			return err
		}
		return json.Unmarshal(value, &manifest)
	})
	if err != nil {
		t.Fatalf("read snapshot manifest: %v", err)
	}
	return manifest
}

func reputationTestSnapshotChunkKeys(t *testing.T, s *BadgerStore) [][]byte {
	t.Helper()
	var keys [][]byte
	err := s.db.View(func(txn *badger.Txn) error {
		options := badger.DefaultIteratorOptions
		options.PrefetchValues = false
		iterator := txn.NewIterator(options)
		defer iterator.Close()
		prefix := []byte(reputationSnapshotChunkPrefix)
		for iterator.Seek(prefix); iterator.ValidForPrefix(prefix); iterator.Next() {
			keys = append(keys, iterator.Item().KeyCopy(nil))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("list snapshot chunks: %v", err)
	}
	return keys
}

func writeReputationTestValue(t *testing.T, s *BadgerStore, key, value []byte) {
	t.Helper()
	if err := s.db.Update(func(txn *badger.Txn) error {
		return txn.Set(key, value)
	}); err != nil {
		t.Fatalf("write raw value %q: %v", key, err)
	}
}

func TestReputationSnapshotNoPriorAndRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	got, err := s.LoadReputationSnapshot(ctx)
	if err != nil {
		t.Fatalf("LoadReputationSnapshot(no prior): %v", err)
	}
	if got != nil {
		t.Fatalf("LoadReputationSnapshot(no prior) = %+v, want nil", *got)
	}

	want := reputationTestSnapshot(3, "config-roundtrip")
	if err := s.SaveReputationSnapshot(ctx, want); err != nil {
		t.Fatalf("SaveReputationSnapshot: %v", err)
	}
	got, err = s.LoadReputationSnapshot(ctx)
	if err != nil {
		t.Fatalf("LoadReputationSnapshot: %v", err)
	}
	assertReputationSnapshotEqual(t, want, got)
	if len(reputationTestSnapshotChunkKeys(t, s)) != 1 {
		t.Fatalf("three scores did not fit in one bounded chunk")
	}
}

func TestReputationSnapshotZeroValidUntilAndEmptyGraph(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	want := &reputation.Snapshot{
		ConfigID:     "config-empty",
		CalculatedAt: time.Date(2026, 4, 5, 6, 7, 8, 0, time.UTC),
		ValidUntil:   time.Time{},
		Coverage:     1,
		Nodes:        0,
		Edges:        0,
		Scores:       map[nostr.PubKey]reputation.Score{},
	}
	if err := s.SaveReputationSnapshot(ctx, want); err != nil {
		t.Fatalf("SaveReputationSnapshot(empty): %v", err)
	}
	got, err := s.LoadReputationSnapshot(ctx)
	if err != nil {
		t.Fatalf("LoadReputationSnapshot(empty): %v", err)
	}
	assertReputationSnapshotEqual(t, want, got)
	if got.Scores == nil {
		t.Fatal("empty snapshot scores decoded as nil map")
	}
	if !got.ValidUntil.IsZero() {
		t.Fatalf("zero valid_until was not preserved: %v", got.ValidUntil)
	}
	if keys := reputationTestSnapshotChunkKeys(t, s); len(keys) != 0 {
		t.Fatalf("empty snapshot wrote %d chunks", len(keys))
	}
}

func TestReputationSnapshotMultiChunkReopen(t *testing.T) {
	path := t.TempDir()
	ctx := context.Background()
	want := reputationTestSnapshot(2*snapshotChunkEntries+37, "config-reopen")
	want.ValidUntil = want.CalculatedAt.Add(48 * time.Hour)

	s, err := NewBadgerStore(&config.DBConfig{Path: path})
	if err != nil {
		t.Fatalf("NewBadgerStore: %v", err)
	}
	if err := s.SaveReputationSnapshot(ctx, want); err != nil {
		_ = s.Close()
		t.Fatalf("SaveReputationSnapshot: %v", err)
	}
	keys := reputationTestSnapshotChunkKeys(t, s)
	if len(keys) != 3 {
		_ = s.Close()
		t.Fatalf("wrote %d chunks, want 3", len(keys))
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s, err = NewBadgerStore(&config.DBConfig{Path: path})
	if err != nil {
		t.Fatalf("reopen NewBadgerStore: %v", err)
	}
	defer func() {
		if err := s.Close(); err != nil {
			t.Fatalf("Close reopened store: %v", err)
		}
	}()

	got, err := s.LoadReputationSnapshot(ctx)
	if err != nil {
		t.Fatalf("LoadReputationSnapshot after reopen: %v", err)
	}
	assertReputationSnapshotEqual(t, want, got)
}

func TestReputationSnapshotFailedGenerationKeepsOldManifest(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	oldSnapshot := reputationTestSnapshot(5, "config-old")
	if err := s.SaveReputationSnapshot(ctx, oldSnapshot); err != nil {
		t.Fatalf("SaveReputationSnapshot(old): %v", err)
	}
	oldManifest := readReputationTestSnapshotManifest(t, s)

	injected := errors.New("injected failure")
	newSnapshot := reputationTestSnapshot(7, "config-new")
	err := s.saveReputationSnapshot(ctx, newSnapshot, func() error { return injected })
	if !errors.Is(err, injected) {
		t.Fatalf("interrupted save error = %v, want injected failure", err)
	}

	afterManifest := readReputationTestSnapshotManifest(t, s)
	if afterManifest.Generation != oldManifest.Generation {
		t.Fatalf("failed save moved manifest from %s to %s", oldManifest.Generation, afterManifest.Generation)
	}
	got, err := s.LoadReputationSnapshot(ctx)
	if err != nil {
		t.Fatalf("LoadReputationSnapshot after failed save: %v", err)
	}
	assertReputationSnapshotEqual(t, oldSnapshot, got)
	for _, key := range reputationTestSnapshotChunkKeys(t, s) {
		generation, ok := parseSnapshotChunkKey(key)
		if !ok || generation != oldManifest.Generation {
			t.Fatalf("failed save left foreign chunk %q", key)
		}
	}

	// A later successful save retires the old generation's chunks.
	if err := s.SaveReputationSnapshot(ctx, newSnapshot); err != nil {
		t.Fatalf("SaveReputationSnapshot(new): %v", err)
	}
	got, err = s.LoadReputationSnapshot(ctx)
	if err != nil {
		t.Fatalf("LoadReputationSnapshot(new): %v", err)
	}
	assertReputationSnapshotEqual(t, newSnapshot, got)
	newManifest := readReputationTestSnapshotManifest(t, s)
	for _, key := range reputationTestSnapshotChunkKeys(t, s) {
		generation, ok := parseSnapshotChunkKey(key)
		if !ok || generation != newManifest.Generation {
			t.Fatalf("retired generation chunk %q was not cleaned", key)
		}
	}
}

func TestReputationSnapshotCorruptActiveGeneration(t *testing.T) {
	corrupt := func(t *testing.T, s *BadgerStore, mutation func([]byte) []byte) {
		t.Helper()
		keys := reputationTestSnapshotChunkKeys(t, s)
		if len(keys) != 1 {
			t.Fatalf("test snapshot has %d chunks, want 1", len(keys))
		}
		var value []byte
		if err := s.db.View(func(txn *badger.Txn) error {
			item, err := txn.Get(keys[0])
			if err != nil {
				return err
			}
			value, err = item.ValueCopy(nil)
			return err
		}); err != nil {
			t.Fatalf("read chunk: %v", err)
		}
		writeReputationTestValue(t, s, keys[0], mutation(value))
	}

	t.Run("missing chunk", func(t *testing.T) {
		s := newTestStore(t)
		if err := s.SaveReputationSnapshot(context.Background(), reputationTestSnapshot(3, "cfg")); err != nil {
			t.Fatalf("SaveReputationSnapshot: %v", err)
		}
		keys := reputationTestSnapshotChunkKeys(t, s)
		if err := s.db.Update(func(txn *badger.Txn) error { return txn.Delete(keys[0]) }); err != nil {
			t.Fatalf("delete chunk: %v", err)
		}
		if _, err := s.LoadReputationSnapshot(context.Background()); err == nil {
			t.Fatal("LoadReputationSnapshot accepted a missing active chunk")
		}
	})

	t.Run("malformed chunk", func(t *testing.T) {
		s := newTestStore(t)
		if err := s.SaveReputationSnapshot(context.Background(), reputationTestSnapshot(3, "cfg")); err != nil {
			t.Fatalf("SaveReputationSnapshot: %v", err)
		}
		corrupt(t, s, func([]byte) []byte { return []byte("{not-json") })
		if _, err := s.LoadReputationSnapshot(context.Background()); err == nil {
			t.Fatal("LoadReputationSnapshot accepted malformed JSON")
		}
	})

	t.Run("digest mismatch", func(t *testing.T) {
		s := newTestStore(t)
		if err := s.SaveReputationSnapshot(context.Background(), reputationTestSnapshot(3, "cfg")); err != nil {
			t.Fatalf("SaveReputationSnapshot: %v", err)
		}
		corrupt(t, s, func(value []byte) []byte {
			var records []scoreRecord
			if err := json.Unmarshal(value, &records); err != nil {
				t.Fatalf("decode chunk: %v", err)
			}
			records[0].PageRank += 0.25
			encoded, err := json.Marshal(records)
			if err != nil {
				t.Fatalf("encode chunk: %v", err)
			}
			return encoded
		})
		if _, err := s.LoadReputationSnapshot(context.Background()); err == nil {
			t.Fatal("LoadReputationSnapshot accepted a valid-JSON chunk with a stale digest")
		}
	})
}

func TestReputationSnapshotReadersStayConsistentDuringRetirement(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	snapshots := []*reputation.Snapshot{
		reputationTestSnapshot(3, "generation-0"),
		reputationTestSnapshot(2*snapshotChunkEntries+5, "generation-1"),
		reputationTestSnapshot(7, "generation-2"),
		reputationTestSnapshot(snapshotChunkEntries, "generation-3"),
	}
	if err := s.SaveReputationSnapshot(ctx, snapshots[0]); err != nil {
		t.Fatalf("SaveReputationSnapshot(first): %v", err)
	}

	stop := make(chan struct{})
	errs := make(chan error, 4)
	var readers sync.WaitGroup
	for i := 0; i < 4; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				snapshot, err := s.LoadReputationSnapshot(ctx)
				if err != nil {
					errs <- fmt.Errorf("concurrent LoadReputationSnapshot: %w", err)
					return
				}
				if snapshot == nil {
					errs <- errors.New("concurrent LoadReputationSnapshot returned no snapshot")
					return
				}
				if len(snapshot.Scores) != snapshot.Nodes {
					errs <- fmt.Errorf("reader observed %d scores for %d nodes", len(snapshot.Scores), snapshot.Nodes)
					return
				}
			}
		}()
	}

	for _, snapshot := range snapshots[1:] {
		if err := s.SaveReputationSnapshot(ctx, snapshot); err != nil {
			close(stop)
			readers.Wait()
			t.Fatalf("SaveReputationSnapshot(%s): %v", snapshot.ConfigID, err)
		}
	}
	close(stop)
	readers.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

func TestReputationSnapshotValidation(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	if err := s.SaveReputationSnapshot(ctx, nil); err == nil {
		t.Fatal("SaveReputationSnapshot accepted nil")
	}

	tests := []struct {
		name   string
		mutate func(*reputation.Snapshot)
	}{
		{name: "zero calculated_at", mutate: func(snapshot *reputation.Snapshot) { snapshot.CalculatedAt = time.Time{} }},
		{name: "negative coverage", mutate: func(snapshot *reputation.Snapshot) { snapshot.Coverage = -0.1 }},
		{name: "coverage above one", mutate: func(snapshot *reputation.Snapshot) { snapshot.Coverage = 1.1 }},
		{name: "NaN coverage", mutate: func(snapshot *reputation.Snapshot) { snapshot.Coverage = math.NaN() }},
		{name: "negative nodes", mutate: func(snapshot *reputation.Snapshot) { snapshot.Nodes = -1 }},
		{name: "negative edges", mutate: func(snapshot *reputation.Snapshot) { snapshot.Edges = -1 }},
		{name: "scores exceed nodes", mutate: func(snapshot *reputation.Snapshot) { snapshot.Nodes = 0 }},
		{name: "NaN page rank", mutate: func(snapshot *reputation.Snapshot) {
			snapshot.Scores[snapshotTestPubKey(0)] = reputation.Score{PageRank: math.NaN()}
		}},
		{name: "infinite trust rank", mutate: func(snapshot *reputation.Snapshot) {
			snapshot.Scores[snapshotTestPubKey(0)] = reputation.Score{TrustRank: math.Inf(1)}
		}},
		{name: "negative page rank", mutate: func(snapshot *reputation.Snapshot) {
			snapshot.Scores[snapshotTestPubKey(0)] = reputation.Score{PageRank: -0.5}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := reputationTestSnapshot(1, "invalid")
			test.mutate(snapshot)
			if err := s.SaveReputationSnapshot(ctx, snapshot); err == nil {
				t.Fatalf("SaveReputationSnapshot accepted %s", test.name)
			}
			if manifest, err := s.LoadReputationSnapshot(ctx); err != nil || manifest != nil {
				t.Fatalf("invalid save changed storage: snapshot=%v err=%v", manifest, err)
			}
		})
	}

	// One score may occupy a graph with additional unscored nodes.
	tolerated := reputationTestSnapshot(1, "valid")
	tolerated.Nodes = 2
	if err := s.SaveReputationSnapshot(ctx, tolerated); err != nil {
		t.Fatalf("SaveReputationSnapshot with unscored nodes: %v", err)
	}
}

func TestReputationSnapshotRejectsOverlongConfigIDWithoutPublishing(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	oldSnapshot := reputationTestSnapshot(4, "config-before-invalid-id")
	if err := s.SaveReputationSnapshot(ctx, oldSnapshot); err != nil {
		t.Fatalf("SaveReputationSnapshot(old): %v", err)
	}
	oldManifest := readReputationTestSnapshotManifest(t, s)
	oldKeys := reputationTestSnapshotChunkKeys(t, s)

	invalid := reputationTestSnapshot(6, strings.Repeat("x", maxSnapshotConfigIDBytes+1))
	err := s.SaveReputationSnapshot(ctx, invalid)
	if err == nil {
		t.Fatal("SaveReputationSnapshot accepted an overlong config ID")
	}
	if !strings.Contains(err.Error(), "config ID") {
		t.Fatalf("overlong config ID error = %v, want a config ID validation error", err)
	}

	// The loader rejects overlong ConfigIDs, so the invalid generation must
	// never have been written or published.
	afterManifest := readReputationTestSnapshotManifest(t, s)
	if afterManifest.Generation != oldManifest.Generation {
		t.Fatalf("invalid save moved manifest from %s to %s", oldManifest.Generation, afterManifest.Generation)
	}
	afterKeys := reputationTestSnapshotChunkKeys(t, s)
	if len(afterKeys) != len(oldKeys) {
		t.Fatalf("invalid save left %d chunks, want the original %d", len(afterKeys), len(oldKeys))
	}
	oldKeySet := make(map[string]struct{}, len(oldKeys))
	for _, key := range oldKeys {
		oldKeySet[string(key)] = struct{}{}
	}
	for _, key := range afterKeys {
		if _, ok := oldKeySet[string(key)]; !ok {
			t.Fatalf("invalid save left foreign chunk %q", key)
		}
	}
	got, err := s.LoadReputationSnapshot(ctx)
	if err != nil {
		t.Fatalf("LoadReputationSnapshot after invalid save: %v", err)
	}
	assertReputationSnapshotEqual(t, oldSnapshot, got)
}

func TestReputationSnapshotContextCancellation(t *testing.T) {
	s := newTestStore(t)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()

	if err := s.SaveReputationSnapshot(canceled, reputationTestSnapshot(1, "cfg")); !errors.Is(err, context.Canceled) {
		t.Fatalf("SaveReputationSnapshot with canceled context error = %v, want context.Canceled", err)
	}
	if _, err := s.LoadReputationSnapshot(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("LoadReputationSnapshot with canceled context error = %v, want context.Canceled", err)
	}
	if got, err := s.LoadReputationSnapshot(context.Background()); err != nil || got != nil {
		t.Fatalf("canceled snapshot save left data behind: snapshot=%v err=%v", got, err)
	}
	if keys := reputationTestSnapshotChunkKeys(t, s); len(keys) != 0 {
		t.Fatalf("canceled snapshot save wrote %d chunks", len(keys))
	}

	want := reputationTestSnapshot(2, "cfg")
	if err := s.SaveReputationSnapshot(context.Background(), want); err != nil {
		t.Fatalf("SaveReputationSnapshot after cancellation: %v", err)
	}
	got, err := s.LoadReputationSnapshot(context.Background())
	if err != nil {
		t.Fatalf("LoadReputationSnapshot: %v", err)
	}
	assertReputationSnapshotEqual(t, want, got)
}
