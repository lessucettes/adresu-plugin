package store

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/dgraph-io/badger/v4"

	"github.com/lessucettes/adresu-plugin/internal/config"
)

const (
	banPrefix              = "ban:"
	moderationActionPrefix = "moderation-action:"
)

// Store is the ban and moderation storage contract. Reputation storage uses
// a separate interface owned by internal/reputation.
type Store interface {
	IsAuthorBanned(ctx context.Context, pubkey string) (bool, error)
	// BanAuthor adds or extends a ban without reducing its existing expiry.
	BanAuthor(ctx context.Context, pubkey string, duration time.Duration) error
	UnbanAuthor(ctx context.Context, pubkey string) error
	// ApplyModeration atomically records a signed moderator action and applies
	// its ban (banDuration > 0) or unban (banDuration == 0). It reports whether
	// this call applied the action; replays return false without side effects.
	ApplyModeration(ctx context.Context, actionID, pubkey string, banDuration time.Duration) (bool, error)
	Close() error
}

// BadgerStore is the production-ready implementation of the Store interface using BadgerDB.
type BadgerStore struct {
	db  *badger.DB
	now func() time.Time
}

// normalizePubkey keeps ban keys on the canonical lowercase representation,
// regardless of how the caller spelled the public key.
func normalizePubkey(pubkey string) string {
	return strings.ToLower(pubkey)
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

	return &BadgerStore{db: db, now: time.Now}, nil
}

// Close gracefully closes the database connection.
func (s *BadgerStore) Close() error {
	return s.db.Close()
}

// getBoundedValue reads a Badger value after checking its reported size, then
// checks the actual size as well. This keeps decoding of a corrupt database
// from allocating an unbounded buffer.
func getBoundedValue(txn *badger.Txn, key []byte, maximum int) ([]byte, bool, error) {
	item, err := txn.Get(key)
	if errors.Is(err, badger.ErrKeyNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if size := item.ValueSize(); size > int64(maximum) {
		return nil, true, fmt.Errorf("value for %q is %d bytes, maximum is %d", key, size, maximum)
	}
	value, err := item.ValueCopy(nil)
	if err != nil {
		return nil, true, err
	}
	if len(value) > maximum {
		return nil, true, fmt.Errorf("value for %q is %d bytes, maximum is %d", key, len(value), maximum)
	}
	return value, true, nil
}

// IsAuthorBanned checks if a given pubkey is in the ban list.
func (s *BadgerStore) IsAuthorBanned(ctx context.Context, pubkey string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}

	key := []byte(banPrefix + normalizePubkey(pubkey))
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

// banExpiry converts a ban deadline to Badger's whole-second expiry. Rounding
// up keeps a positive requested duration intact instead of truncating it, and
// ensures a sub-second ban is not stored already expired.
func banExpiry(now time.Time, duration time.Duration) uint64 {
	deadline := now.Add(duration)
	expiresAt := deadline.Unix()
	if deadline.Nanosecond() != 0 {
		expiresAt++
	}
	return uint64(expiresAt)
}

func newBanEntry(key []byte, now time.Time, duration time.Duration) *badger.Entry {
	entry := badger.NewEntry(key, nil)
	if duration > 0 {
		entry.ExpiresAt = banExpiry(now, duration)
		return entry
	}
	// Preserve the previous behavior of non-positive BanAuthor durations while
	// keeping time injection consistent with the rest of the store.
	entry.ExpiresAt = uint64(now.Add(duration).Unix())
	return entry
}

// setBanEntry writes a ban unless an existing ban already expires at the same
// time or later. This keeps shorter automatic or moderator bans from reducing
// a longer ban written earlier.
func setBanEntry(txn *badger.Txn, key []byte, entry *badger.Entry) error {
	item, err := txn.Get(key)
	if err != nil && !errors.Is(err, badger.ErrKeyNotFound) {
		return err
	}
	if err == nil && (item.ExpiresAt() == 0 || item.ExpiresAt() >= entry.ExpiresAt) {
		return nil
	}
	return txn.SetEntry(entry)
}

// BanAuthor adds or extends a ban, never shortening an existing ban. Removing
// or deliberately shortening a ban requires UnbanAuthor first.
func (s *BadgerStore) BanAuthor(ctx context.Context, pubkey string, duration time.Duration) error {
	// Badger transactions cannot be cancelled, but honor an already canceled
	// or expired context so callers' timeouts are not silently ignored.
	if err := ctx.Err(); err != nil {
		return err
	}

	normalizedPubkey := normalizePubkey(pubkey)
	slog.Info("Banning author", "pubkey", normalizedPubkey, "duration", duration.String())
	key := []byte(banPrefix + normalizedPubkey)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := s.db.Update(func(txn *badger.Txn) error {
			return setBanEntry(txn, key, newBanEntry(key, s.now(), duration))
		})
		if !errors.Is(err, badger.ErrConflict) {
			return err
		}
		// A concurrent ban/unban changed the key after this transaction read
		// it. Re-evaluate the expiry instead of overwriting that newer state.
	}
}

// ApplyModeration records a moderator action and its ban or unban in one
// Badger transaction. The marker has no TTL: once a signed moderator action has
// taken effect, replays must remain harmless even after a reload or restart.
func (s *BadgerStore) ApplyModeration(ctx context.Context, actionID, pubkey string, banDuration time.Duration) (bool, error) {
	if banDuration < 0 {
		return false, fmt.Errorf("moderation ban duration must not be negative: %s", banDuration)
	}
	if actionID == "" {
		return false, errors.New("moderation action ID must not be empty")
	}

	normalizedPubkey := normalizePubkey(pubkey)
	banKey := []byte(banPrefix + normalizedPubkey)
	actionKey := []byte(moderationActionPrefix + actionID)

	for {
		// Badger cannot cancel a running transaction, but stop retrying and
		// starting new transactions once the caller's context is done.
		if err := ctx.Err(); err != nil {
			return false, err
		}

		applied := false
		err := s.db.Update(func(txn *badger.Txn) error {
			if _, err := txn.Get(actionKey); err == nil {
				return nil
			} else if !errors.Is(err, badger.ErrKeyNotFound) {
				return err
			}

			if banDuration > 0 {
				entry := newBanEntry(banKey, s.now(), banDuration)
				if err := setBanEntry(txn, banKey, entry); err != nil {
					return err
				}
			} else if err := txn.Delete(banKey); err != nil {
				return err
			}

			if err := txn.SetEntry(badger.NewEntry(actionKey, nil)); err != nil {
				return err
			}
			applied = true
			return nil
		})
		if errors.Is(err, badger.ErrConflict) {
			continue
		}
		if err != nil {
			return false, fmt.Errorf("failed to apply moderation action: %w", err)
		}
		return applied, nil
	}
}

// UnbanAuthor removes a pubkey from the ban list in the database.
func (s *BadgerStore) UnbanAuthor(ctx context.Context, pubkey string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	normalizedPubkey := normalizePubkey(pubkey)
	slog.Info("Unbanning author", "pubkey", normalizedPubkey)
	key := []byte(banPrefix + normalizedPubkey)
	return s.db.Update(func(txn *badger.Txn) error {
		return txn.Delete(key)
	})
}
