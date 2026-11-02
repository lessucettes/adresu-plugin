package store

import (
	"context"
	"errors"

	"github.com/dgraph-io/badger/v4"
)

// deleteSnapshotGeneration removes chunks belonging to one abandoned
// generation without touching any other generation.
func (s *BadgerStore) deleteSnapshotGeneration(ctx context.Context, generation string) error {
	return s.deleteSnapshotChunks(ctx, func(candidate string) bool {
		return candidate == generation
	})
}

// cleanupRetiredSnapshotGenerations removes chunks not referenced by the
// active manifest. Cleanup is batched so it never becomes one large write
// transaction.
func (s *BadgerStore) cleanupRetiredSnapshotGenerations(ctx context.Context, activeGeneration string) error {
	return s.deleteSnapshotChunks(ctx, func(candidate string) bool {
		return candidate != activeGeneration
	})
}

func (s *BadgerStore) deleteSnapshotChunks(ctx context.Context, shouldDelete func(string) bool) error {
	prefix := []byte(reputationSnapshotChunkPrefix)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		var keys [][]byte
		err := s.db.Update(func(txn *badger.Txn) error {
			options := badger.DefaultIteratorOptions
			options.PrefetchValues = false
			iterator := txn.NewIterator(options)
			for iterator.Seek(prefix); iterator.ValidForPrefix(prefix) && len(keys) < snapshotCleanupBatch; iterator.Next() {
				generation, ok := parseSnapshotChunkKey(iterator.Item().Key())
				if ok && shouldDelete(generation) {
					keys = append(keys, iterator.Item().KeyCopy(nil))
				}
			}
			// Close before mutating keys in this transaction; Badger iterators
			// must not be used after deletes, and an explicit close also
			// releases their resources before the batch is applied.
			iterator.Close()
			for _, key := range keys {
				if err := txn.Delete(key); err != nil {
					return err
				}
			}
			return nil
		})
		if errors.Is(err, badger.ErrConflict) {
			keys = nil
			continue
		}
		if err != nil {
			return err
		}
		if len(keys) == 0 {
			return nil
		}
	}
}
