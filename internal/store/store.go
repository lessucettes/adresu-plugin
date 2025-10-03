package store

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/lessucettes/adresu-plugin/internal/config"
)

const banPrefix = "ban:"

// Store is the generic interface for all storage types.
type Store interface {
	IsAuthorBanned(ctx context.Context, pubkey string) (bool, error)
	BanAuthor(ctx context.Context, pubkey string, duration time.Duration) error
	UnbanAuthor(ctx context.Context, pubkey string) error
	Close() error
}

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
func NewBadgerStore(cfg *config.DBConfig) (*BadgerStore, error) {
	opts := badger.DefaultOptions(cfg.Path)
	opts.ValueThreshold = 1024
	opts.Logger = &badgerLogger{slog.Default()}

	db, err := badger.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to open badger db: %w", err)
	}

	return &BadgerStore{db: db}, nil
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
