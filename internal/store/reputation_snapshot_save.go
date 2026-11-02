package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/dgraph-io/badger/v4"

	"github.com/lessucettes/adresu-plugin/pkg/adresu-kit/reputation"
)

// snapshotSaveLock serializes snapshot writers. The runtime owns a single
// writer; this token is a safety net against accidental concurrent calls. A
// single package token is used instead of a map keyed by *BadgerStore so it
// cannot retain stores forever.
var snapshotSaveLock = make(chan struct{}, 1)

// lockSnapshotWriter waits for the single snapshot-writer token, honoring
// cancellation while it waits and immediately after acquiring the token.
func lockSnapshotWriter(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case snapshotSaveLock <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-snapshotSaveLock
			return err
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func unlockSnapshotWriter() {
	<-snapshotSaveLock
}

// SaveReputationSnapshot persists a complete snapshot generation. Chunks are
// written in bounded transactions, then a single manifest key publishes the
// generation. If anything fails before that commit, the old manifest remains
// authoritative; its chunks are never modified in place. ValidUntil is stored
// verbatim; zero is accepted for standalone tests and older data, and the
// runtime decides whether a loaded snapshot is usable.
func (s *BadgerStore) SaveReputationSnapshot(ctx context.Context, snapshot *reputation.Snapshot) error {
	return s.saveReputationSnapshot(ctx, snapshot, nil)
}

// saveReputationSnapshot has an internal pre-commit hook so tests can inject a
// failure after chunks are durable but before the manifest pointer moves.
func (s *BadgerStore) saveReputationSnapshot(ctx context.Context, snapshot *reputation.Snapshot, beforeManifestCommit func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if snapshot == nil {
		return errors.New("reputation snapshot must not be nil")
	}
	if err := validateSnapshotForSave(snapshot); err != nil {
		return fmt.Errorf("validate reputation snapshot: %w", err)
	}
	if err := lockSnapshotWriter(ctx); err != nil {
		return err
	}
	defer unlockSnapshotWriter()

	generation, err := newSnapshotGeneration()
	if err != nil {
		return err
	}
	expectedChunks := (len(snapshot.Scores) + snapshotChunkEntries - 1) / snapshotChunkEntries
	digest := sha256.New()

	// discardNewGeneration removes only chunks written by this failed call.
	// It uses a detached, bounded context so cleanup is attempted even when
	// the caller's context was canceled. Failure is only logged; the old
	// generation is still readable either way.
	discardNewGeneration := func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), snapshotCleanupTimeout)
		defer cancel()
		if err := s.deleteSnapshotGeneration(cleanupCtx, generation); err != nil {
			slog.Warn("failed to remove incomplete reputation snapshot generation",
				"generation", generation, "error", err)
		}
	}

	chunk := make([]scoreRecord, 0, snapshotChunkEntries)
	chunkIndex := 0
	flush := func() error {
		data, err := json.Marshal(chunk)
		if err != nil {
			return fmt.Errorf("marshal snapshot chunk %d: %w", chunkIndex, err)
		}
		if len(data) > maxSnapshotChunkBytes {
			return fmt.Errorf("snapshot chunk %d is %d bytes, maximum is %d", chunkIndex, len(data), maxSnapshotChunkBytes)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := s.db.Update(func(txn *badger.Txn) error {
			return txn.Set(snapshotChunkKey(generation, chunkIndex), data)
		}); err != nil {
			return fmt.Errorf("write snapshot chunk %d: %w", chunkIndex, err)
		}
		addSnapshotChunkDigest(digest, chunkIndex, data)
		chunkIndex++
		chunk = chunk[:0]
		return nil
	}

	for pubkey, score := range snapshot.Scores {
		if err := ctx.Err(); err != nil {
			discardNewGeneration()
			return err
		}
		chunk = append(chunk, scoreRecord{
			PubKey:    pubkey.Hex(),
			PageRank:  score.PageRank,
			TrustRank: score.TrustRank,
		})
		if len(chunk) == snapshotChunkEntries {
			if err := flush(); err != nil {
				discardNewGeneration()
				return err
			}
		}
	}
	if len(chunk) > 0 {
		if err := flush(); err != nil {
			discardNewGeneration()
			return err
		}
	}
	if chunkIndex != expectedChunks {
		discardNewGeneration()
		return fmt.Errorf("wrote %d snapshot chunks, expected %d", chunkIndex, expectedChunks)
	}

	manifest := snapshotManifest{
		Format:       snapshotFormatVersion,
		Generation:   generation,
		ChunkEntries: snapshotChunkEntries,
		ChunkCount:   chunkIndex,
		ScoreCount:   len(snapshot.Scores),
		ChunkDigest:  hex.EncodeToString(digest.Sum(nil)),
		ConfigID:     snapshot.ConfigID,
		CalculatedAt: snapshot.CalculatedAt,
		ValidUntil:   snapshot.ValidUntil,
		Coverage:     snapshot.Coverage,
		Nodes:        snapshot.Nodes,
		Edges:        snapshot.Edges,
	}
	manifestValue, err := json.Marshal(manifest)
	if err != nil {
		discardNewGeneration()
		return fmt.Errorf("marshal snapshot manifest: %w", err)
	}
	if len(manifestValue) > maxSnapshotManifestBytes {
		discardNewGeneration()
		return fmt.Errorf("snapshot manifest is %d bytes, maximum is %d", len(manifestValue), maxSnapshotManifestBytes)
	}
	if beforeManifestCommit != nil {
		if err := beforeManifestCommit(); err != nil {
			discardNewGeneration()
			return fmt.Errorf("snapshot save interrupted before manifest commit: %w", err)
		}
	}
	if err := ctx.Err(); err != nil {
		discardNewGeneration()
		return err
	}

	// The manifest is the single atomic publish point.
	if err := s.db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte(reputationSnapshotManifestKey), manifestValue)
	}); err != nil {
		discardNewGeneration()
		return fmt.Errorf("commit reputation snapshot manifest: %w", err)
	}

	// Old generations are retired only after the new manifest is visible.
	// Cleanup is best effort: the committed snapshot is already durable, and
	// a later save will retry any leftovers.
	if err := s.cleanupRetiredSnapshotGenerations(ctx, generation); err != nil && ctx.Err() == nil {
		slog.Warn("failed to clean retired reputation snapshot generations", "error", err)
	}
	return nil
}
