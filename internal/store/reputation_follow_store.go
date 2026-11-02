package store

import (
	"context"
	"errors"
	"fmt"

	"fiatjaf.com/nostr"
	"github.com/dgraph-io/badger/v4"

	"github.com/lessucettes/adresu-plugin/pkg/adresu-kit/reputation"
)

// readFollowListRecord reads a body key with a size bound applied before any
// allocation or decode.
func readFollowListRecord(txn *badger.Txn, key []byte) (reputation.FollowList, bool, error) {
	value, found, err := getBoundedValue(txn, key, maxFollowListBytes)
	if err != nil || !found {
		return reputation.FollowList{}, found, err
	}
	list, err := decodeFollowListRecord(key, value)
	if err != nil {
		return reputation.FollowList{}, true, err
	}
	return list, true, nil
}

// readFollowReceipt reads the small receipt header for one author. A missing
// header means the row predates receipts and the body is authoritative.
func readFollowReceipt(txn *badger.Txn, key []byte) (followReceipt, bool, error) {
	value, found, err := getBoundedValue(txn, key, maxFollowReceiptBytes)
	if err != nil || !found {
		return followReceipt{}, found, err
	}
	receipt, err := decodeFollowReceipt(key, value)
	if err != nil {
		return followReceipt{}, true, err
	}
	return receipt, true, nil
}

func writeFollowReceipt(txn *badger.Txn, key []byte, receipt followReceipt) error {
	value, err := encodeFollowReceipt(receipt)
	if err != nil {
		return fmt.Errorf("encode follow list receipt: %w", err)
	}
	return txn.Set(key, value)
}

// writeFollowList writes the body and its receipt in the caller's transaction,
// so replacement is a single atomic publish and a reader never observes a body
// from one signed event with a receipt from another.
func writeFollowList(txn *badger.Txn, bodyKey, receiptKey []byte, list reputation.FollowList) error {
	body, err := encodeFollowList(list)
	if err != nil {
		return fmt.Errorf("validate follow list: %w", err)
	}
	if err := txn.Set(bodyKey, body); err != nil {
		return err
	}
	return writeFollowReceipt(txn, receiptKey, followReceipt{
		EventID:   list.EventID,
		CreatedAt: list.CreatedAt,
		FetchedAt: list.FetchedAt,
	})
}

// SaveFollowList atomically stores the latest verified kind-3 list for its
// author. Older versions, and same-timestamp versions with a larger event ID,
// are ignored without error so callers can replay signed events safely.
//
// A refresh of an already stored signed event only advances the small receipt
// header: the immutable body is neither read nor rewritten. A replacement
// writes body and receipt together. Rows written before receipts existed are
// upgraded lazily on the first save that observes them, using the body's own
// version and FetchedAt, and never roll the observation time back.
func (s *BadgerStore) SaveFollowList(ctx context.Context, list reputation.FollowList) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateFollowList(list); err != nil {
		return fmt.Errorf("validate follow list: %w", err)
	}

	bodyKey := followListKey(list.Author)
	receiptKey := followReceiptKey(list.Author)
	candidate := followReceipt{
		EventID:   list.EventID,
		CreatedAt: list.CreatedAt,
		FetchedAt: list.FetchedAt.UTC(),
	}

	for {
		// Badger cannot abort an in-flight transaction, but stop starting
		// new retries as soon as the caller is done.
		if err := ctx.Err(); err != nil {
			return err
		}

		err := s.db.Update(func(txn *badger.Txn) error {
			receipt, hasReceipt, err := readFollowReceipt(txn, receiptKey)
			if err != nil {
				return err
			}
			if hasReceipt {
				if sameFollowListVersion(receipt.EventID, receipt.CreatedAt, list) {
					// Same signed event: only the observation time may move,
					// and only forward. The body is not copied or decoded;
					// the lookup is only a metadata check that it still
					// exists, since a header without a body is corruption.
					if _, err := txn.Get(bodyKey); err != nil {
						if errors.Is(err, badger.ErrKeyNotFound) {
							return fmt.Errorf("follow list %q has a receipt but no body", bodyKey)
						}
						return err
					}
					if !candidate.FetchedAt.After(receipt.FetchedAt) {
						return nil
					}
					receipt.FetchedAt = candidate.FetchedAt
					return writeFollowReceipt(txn, receiptKey, receipt)
				}

				existing, found, err := readFollowListRecord(txn, bodyKey)
				if err != nil {
					return err
				}
				if !found {
					return fmt.Errorf("follow list %q has a receipt but no body", bodyKey)
				}
				if !receiptMatchesFollowList(receipt, existing) {
					return fmt.Errorf("follow list %q receipt does not match its stored body", bodyKey)
				}
				if !followListSupersedes(list, existing) {
					return nil
				}
				return writeFollowList(txn, bodyKey, receiptKey, list)
			}

			// No receipt: either a new author or a row written before
			// receipts existed. Read the body to establish its signed
			// version, then materialize the receipt exactly once.
			existing, found, err := readFollowListRecord(txn, bodyKey)
			if err != nil {
				return err
			}
			if !found {
				return writeFollowList(txn, bodyKey, receiptKey, list)
			}
			if sameFollowListVersion(existing.EventID, existing.CreatedAt, list) {
				fetchedAt := existing.FetchedAt
				if candidate.FetchedAt.After(fetchedAt) {
					fetchedAt = candidate.FetchedAt
				}
				return writeFollowReceipt(txn, receiptKey, followReceipt{
					EventID:   existing.EventID,
					CreatedAt: existing.CreatedAt,
					FetchedAt: fetchedAt,
				})
			}
			if !followListSupersedes(list, existing) {
				// The candidate loses, but the legacy row still gets its
				// receipt so future refreshes can take the cheap path.
				return writeFollowReceipt(txn, receiptKey, followReceipt{
					EventID:   existing.EventID,
					CreatedAt: existing.CreatedAt,
					FetchedAt: existing.FetchedAt,
				})
			}
			return writeFollowList(txn, bodyKey, receiptKey, list)
		})
		if errors.Is(err, badger.ErrConflict) {
			// A concurrent save changed a key after this transaction read
			// it. Re-read and re-evaluate instead of overwriting its answer.
			continue
		}
		if err != nil {
			return fmt.Errorf("save follow list: %w", err)
		}
		return nil
	}
}

// LoadFollowList returns the stored follow list for one author. It returns
// (nil, nil) when no list has been saved for that author, allowing the
// collector to distinguish absence from an authored empty list.
//
// The receipt version must match the body, and the effective FetchedAt is the
// later of the receipt and the body. Taking the maximum keeps reads correct if
// a pre-receipt writer refreshed the body after the header was created.
func (s *BadgerStore) LoadFollowList(ctx context.Context, author nostr.PubKey) (*reputation.FollowList, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	bodyKey := followListKey(author)
	receiptKey := followReceiptKey(author)
	var list *reputation.FollowList
	err := s.db.View(func(txn *badger.Txn) error {
		receipt, hasReceipt, err := readFollowReceipt(txn, receiptKey)
		if err != nil {
			return err
		}
		existing, found, err := readFollowListRecord(txn, bodyKey)
		if err != nil {
			return err
		}
		if !found {
			if hasReceipt {
				return fmt.Errorf("follow list %q has a receipt but no body", bodyKey)
			}
			return nil
		}
		if hasReceipt {
			if !receiptMatchesFollowList(receipt, existing) {
				return fmt.Errorf("follow list %q receipt does not match its stored body", bodyKey)
			}
			if receipt.FetchedAt.After(existing.FetchedAt) {
				existing.FetchedAt = receipt.FetchedAt
			}
		}
		list = &existing
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("load follow list: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return list, nil
}
