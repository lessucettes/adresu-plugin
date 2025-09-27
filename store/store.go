package store

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/dgraph-io/badger/v4"
)

const banPrefix = "ban:"

// Store is the generic interface for all storage types.
// It allows for easy swapping of the real database with a mock in tests.
type Store interface {
	IsAuthorBanned(ctx context.Context, pubkey string) (bool, error)
	BanAuthor(ctx context.Context, pubkey string, duration time.Duration) error
	UnbanAuthor(ctx context.Context, pubkey string) error
	Close() error
}

// --- BADGERDB IMPLEMENTATION (PRODUCTION) ---

// BadgerStore is the production-ready implementation of the Store interface using BadgerDB.
type BadgerStore struct {
	db *badger.DB
}

// badgerLogger adapts slog.Logger to be used as a logger for BadgerDB.
type badgerLogger struct {
	*slog.Logger
}

func (l *badgerLogger) Warningf(f string, v ...any) { l.Warn(fmt.Sprintf(f, v...)) }
func (l *badgerLogger) Errorf(f string, v ...any)   { l.Error(fmt.Sprintf(f, v...)) }
func (l *badgerLogger) Infof(f string, v ...any)    {}
func (l *badgerLogger) Debugf(f string, v ...any)   {}

// NewBadgerStore initializes and returns a new, optimized BadgerStore.
func NewBadgerStore(path string) (*BadgerStore, error) {
	opts := badger.DefaultOptions(path)

	// Optimization: Set a value threshold. Values smaller than this (1KB) will be
	// stored in the faster LSM-tree instead of the separate value log. Ideal for
	// small data like ban records.
	opts.ValueThreshold = 1024

	// Redirect BadgerDB's internal logs to the application's main slog logger.
	opts.Logger = &badgerLogger{slog.Default()}

	db, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to open badger db: %w", err)
	}

	store := &BadgerStore{
		db: db,
	}

	return store, nil
}

// Close gracefully closes the database connection.
func (s *BadgerStore) Close() error {
	return s.db.Close()
}

// IsAuthorBanned checks if a given pubkey is in the ban list.
func (s *BadgerStore) IsAuthorBanned(ctx context.Context, pubkey string) (bool, error) {
	key := []byte(banPrefix + pubkey)
	err := s.db.View(func(txn *badger.Txn) error {
		_, err := txn.Get(key)
		return err
	})
	if errors.Is(err, badger.ErrKeyNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// BanAuthor adds a pubkey to the ban list with a specified TTL.
// The value is stored as nil to save space, as only the key's existence matters.
func (s *BadgerStore) BanAuthor(ctx context.Context, pubkey string, duration time.Duration) error {
	slog.Info("Banning author", "pubkey", pubkey, "duration", duration.String())
	key := []byte(banPrefix + pubkey)
	return s.db.Update(func(txn *badger.Txn) error {
		entry := badger.NewEntry(key, nil).WithTTL(duration)
		return txn.SetEntry(entry)
	})
}

// UnbanAuthor removes a pubkey from the ban list in the database.
func (s *BadgerStore) UnbanAuthor(ctx context.Context, pubkey string) error {
	slog.Info("Unbanning author", "pubkey", pubkey)
	key := []byte(banPrefix + pubkey)
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Delete(key)
	})
}
