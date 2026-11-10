package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"fiatjaf.com/nostr"
	"github.com/dgraph-io/badger/v4"

	"github.com/lessucettes/adresu-plugin/pkg/adresu-kit/reputation"
)

// LoadReputationSnapshot returns the generation currently published by the
// manifest, or (nil, nil) when no snapshot has ever been saved. A single
// Badger read transaction spans the manifest and every chunk, so concurrent
// retirement cannot make an in-flight read observe a mixed generation.
func (s *BadgerStore) LoadReputationSnapshot(ctx context.Context) (*reputation.Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	var snapshot *reputation.Snapshot
	err := s.db.View(func(txn *badger.Txn) error {
		manifestValue, found, err := getBoundedValue(txn, []byte(reputationSnapshotManifestKey), maxSnapshotManifestBytes)
		if err != nil {
			return fmt.Errorf("read snapshot manifest: %w", err)
		}
		if !found {
			return nil
		}
		var manifest snapshotManifest
		if err := json.Unmarshal(manifestValue, &manifest); err != nil {
			return fmt.Errorf("decode snapshot manifest: %w", err)
		}
		if err := validateSnapshotManifest(manifest); err != nil {
			return fmt.Errorf("invalid snapshot manifest: %w", err)
		}

		scores := make(map[nostr.PubKey]reputation.Score, manifest.ScoreCount)
		digest := sha256.New()
		for index := 0; index < manifest.ChunkCount; index++ {
			if err := ctx.Err(); err != nil {
				return err
			}
			chunkValue, found, err := getBoundedValue(txn, snapshotChunkKey(manifest.Generation, index), maxSnapshotChunkBytes)
			if err != nil {
				return fmt.Errorf("read snapshot chunk %d: %w", index, err)
			}
			if !found {
				return fmt.Errorf("snapshot chunk %d for generation %s is missing", index, manifest.Generation)
			}
			addSnapshotChunkDigest(digest, index, chunkValue)

			var records []scoreRecord
			if err := json.Unmarshal(chunkValue, &records); err != nil {
				return fmt.Errorf("decode snapshot chunk %d: %w", index, err)
			}
			expectedEntries := manifest.ChunkEntries
			if index == manifest.ChunkCount-1 {
				expectedEntries = manifest.ScoreCount - index*manifest.ChunkEntries
			}
			if len(records) != expectedEntries {
				return fmt.Errorf("snapshot chunk %d has %d scores, expected %d", index, len(records), expectedEntries)
			}
			for recordIndex, record := range records {
				pubkey, err := nostr.PubKeyFromHexCheap(record.PubKey)
				if err != nil {
					return fmt.Errorf("snapshot chunk %d record %d: %w", index, recordIndex, err)
				}
				if _, duplicate := scores[pubkey]; duplicate {
					return fmt.Errorf("snapshot chunk %d record %d duplicates pubkey %s", index, recordIndex, pubkey.Hex())
				}
				score := reputation.Score{TrustRank: record.TrustRank}
				if err := validateReputationScore(score); err != nil {
					return fmt.Errorf("snapshot chunk %d record %d: %w", index, recordIndex, err)
				}
				scores[pubkey] = score
			}
		}

		if len(scores) != manifest.ScoreCount {
			return fmt.Errorf("snapshot has %d scores, manifest declares %d", len(scores), manifest.ScoreCount)
		}
		if len(scores) > manifest.Nodes {
			return fmt.Errorf("snapshot has %d scores but only %d nodes", len(scores), manifest.Nodes)
		}
		if actualDigest := hex.EncodeToString(digest.Sum(nil)); actualDigest != manifest.ChunkDigest {
			return fmt.Errorf("snapshot chunk digest mismatch: got %s, want %s", actualDigest, manifest.ChunkDigest)
		}

		snapshot = &reputation.Snapshot{
			ConfigID:     manifest.ConfigID,
			CalculatedAt: manifest.CalculatedAt,
			ValidUntil:   manifest.ValidUntil,
			Coverage:     manifest.Coverage,
			Nodes:        manifest.Nodes,
			Edges:        manifest.Edges,
			Scores:       scores,
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("load reputation snapshot: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return snapshot, nil
}
