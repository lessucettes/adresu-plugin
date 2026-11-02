package store

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"fiatjaf.com/nostr"

	"github.com/lessucettes/adresu-plugin/pkg/adresu-kit/reputation"
)

const (
	// reputationFollowPrefix is deliberately separate from ban: and
	// moderation-action: so graph maintenance never touches moderation state.
	// It is also not a prefix of reputationFollowReceiptPrefix: the next byte
	// differs, so older scanners over the body prefix cannot see receipts.
	reputationFollowPrefix        = "reputation-follow:"
	reputationFollowReceiptPrefix = "reputation-follow-receipt:"

	maxFollowsPerList     = 100_000
	maxFollowListBytes    = 8 << 20
	maxFollowReceiptBytes = 4 << 10
)

// followListRecord is the on-disk body representation. Pubkeys and event IDs
// are explicit hex strings: JSON maps with array keys are not representable,
// and relying on the array's marshaling behavior would couple storage to nostr.
// FetchedAt is retained for rows written before receipts existed; once a
// receipt exists, readers merge both and take the later observation time.
type followListRecord struct {
	Author    string    `json:"author"`
	EventID   string    `json:"event_id"`
	CreatedAt int64     `json:"created_at"`
	FetchedAt time.Time `json:"fetched_at"`
	Follows   []string  `json:"follows"`
}

// followReceiptRecord is the small per-author receipt header. It mirrors the
// signed version in the body so refreshing FetchedAt never has to decode or
// rewrite the (potentially large) follow array.
type followReceiptRecord struct {
	EventID   string    `json:"event_id"`
	CreatedAt int64     `json:"created_at"`
	FetchedAt time.Time `json:"fetched_at"`
}

type followReceipt struct {
	EventID   nostr.ID
	CreatedAt nostr.Timestamp
	FetchedAt time.Time
}

func followListKey(author nostr.PubKey) []byte {
	return []byte(reputationFollowPrefix + author.Hex())
}

func followReceiptKey(author nostr.PubKey) []byte {
	return []byte(reputationFollowReceiptPrefix + author.Hex())
}

// followAuthorFromKey validates that a stored key has the canonical lowercase
// hex form used by the key constructors.
func followAuthorFromKey(key []byte, prefix string) (nostr.PubKey, error) {
	if !bytes.HasPrefix(key, []byte(prefix)) {
		return nostr.PubKey{}, fmt.Errorf("follow list key %q has an unexpected prefix", key)
	}
	encoded := string(key[len(prefix):])
	author, err := nostr.PubKeyFromHexCheap(encoded)
	if err != nil {
		return nostr.PubKey{}, fmt.Errorf("follow list key %q: %w", key, err)
	}
	if author.Hex() != encoded {
		return nostr.PubKey{}, fmt.Errorf("follow list key %q is not canonical lowercase hex", key)
	}
	return author, nil
}

func validateFollowList(list reputation.FollowList) error {
	if list.FetchedAt.IsZero() {
		return errors.New("follow list fetched_at must not be zero")
	}
	if list.CreatedAt < 0 {
		return fmt.Errorf("follow list created_at must not be negative: %d", list.CreatedAt)
	}
	if len(list.Follows) > maxFollowsPerList {
		return fmt.Errorf("follow list has %d entries, maximum is %d", len(list.Follows), maxFollowsPerList)
	}
	return nil
}

func encodeFollowList(list reputation.FollowList) ([]byte, error) {
	if err := validateFollowList(list); err != nil {
		return nil, err
	}

	// make, rather than a nil slice, is what distinguishes a real empty list
	// from a missing author after a round trip.
	follows := make([]string, len(list.Follows))
	for i, follow := range list.Follows {
		follows[i] = follow.Hex()
	}
	record := followListRecord{
		Author:    list.Author.Hex(),
		EventID:   list.EventID.Hex(),
		CreatedAt: int64(list.CreatedAt),
		FetchedAt: list.FetchedAt.UTC(),
		Follows:   follows,
	}
	value, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("marshal follow list: %w", err)
	}
	if len(value) > maxFollowListBytes {
		return nil, fmt.Errorf("encoded follow list is %d bytes, maximum is %d", len(value), maxFollowListBytes)
	}
	return value, nil
}

func decodeFollowListRecord(key, value []byte) (reputation.FollowList, error) {
	var record followListRecord
	if err := json.Unmarshal(value, &record); err != nil {
		return reputation.FollowList{}, fmt.Errorf("decode follow list %q: %w", key, err)
	}

	keyAuthor, err := followAuthorFromKey(key, reputationFollowPrefix)
	if err != nil {
		return reputation.FollowList{}, err
	}
	author, err := nostr.PubKeyFromHexCheap(record.Author)
	if err != nil {
		return reputation.FollowList{}, fmt.Errorf("follow list %q author: %w", key, err)
	}
	if author != keyAuthor {
		return reputation.FollowList{}, fmt.Errorf("follow list %q author %s does not match its key", key, author.Hex())
	}
	eventID, err := nostr.IDFromHex(record.EventID)
	if err != nil {
		return reputation.FollowList{}, fmt.Errorf("follow list %q event id: %w", key, err)
	}
	if record.CreatedAt < 0 {
		return reputation.FollowList{}, fmt.Errorf("follow list %q created_at must not be negative: %d", key, record.CreatedAt)
	}
	if record.FetchedAt.IsZero() {
		return reputation.FollowList{}, fmt.Errorf("follow list %q fetched_at must not be zero", key)
	}
	if record.Follows == nil {
		// The encoder always writes [] for an authored empty list. A missing
		// array is corruption, not the same thing as an empty follow list.
		return reputation.FollowList{}, fmt.Errorf("follow list %q follows must be a JSON array", key)
	}
	if len(record.Follows) > maxFollowsPerList {
		return reputation.FollowList{}, fmt.Errorf("follow list %q has %d entries, maximum is %d", key, len(record.Follows), maxFollowsPerList)
	}

	follows := make([]nostr.PubKey, len(record.Follows))
	for i, encoded := range record.Follows {
		follow, err := nostr.PubKeyFromHexCheap(encoded)
		if err != nil {
			return reputation.FollowList{}, fmt.Errorf("follow list %q entry %d: %w", key, i, err)
		}
		follows[i] = follow
	}

	return reputation.FollowList{
		Author:    author,
		EventID:   eventID,
		CreatedAt: nostr.Timestamp(record.CreatedAt),
		FetchedAt: record.FetchedAt,
		Follows:   follows,
	}, nil
}

func validateFollowReceipt(receipt followReceipt) error {
	if receipt.CreatedAt < 0 {
		return fmt.Errorf("follow list receipt created_at must not be negative: %d", receipt.CreatedAt)
	}
	if receipt.FetchedAt.IsZero() {
		return errors.New("follow list receipt fetched_at must not be zero")
	}
	return nil
}

func encodeFollowReceipt(receipt followReceipt) ([]byte, error) {
	if err := validateFollowReceipt(receipt); err != nil {
		return nil, err
	}
	value, err := json.Marshal(followReceiptRecord{
		EventID:   receipt.EventID.Hex(),
		CreatedAt: int64(receipt.CreatedAt),
		FetchedAt: receipt.FetchedAt.UTC(),
	})
	if err != nil {
		return nil, fmt.Errorf("marshal follow list receipt: %w", err)
	}
	if len(value) > maxFollowReceiptBytes {
		return nil, fmt.Errorf("encoded follow list receipt is %d bytes, maximum is %d", len(value), maxFollowReceiptBytes)
	}
	return value, nil
}

func decodeFollowReceipt(key, value []byte) (followReceipt, error) {
	var record followReceiptRecord
	if err := json.Unmarshal(value, &record); err != nil {
		return followReceipt{}, fmt.Errorf("decode follow list receipt %q: %w", key, err)
	}
	if _, err := followAuthorFromKey(key, reputationFollowReceiptPrefix); err != nil {
		return followReceipt{}, err
	}
	eventID, err := nostr.IDFromHex(record.EventID)
	if err != nil {
		return followReceipt{}, fmt.Errorf("follow list receipt %q event id: %w", key, err)
	}
	receipt := followReceipt{
		EventID:   eventID,
		CreatedAt: nostr.Timestamp(record.CreatedAt),
		FetchedAt: record.FetchedAt.UTC(),
	}
	if err := validateFollowReceipt(receipt); err != nil {
		return followReceipt{}, fmt.Errorf("follow list receipt %q: %w", key, err)
	}
	return receipt, nil
}

// sameFollowListVersion reports whether two observations refer to the same
// signed kind-3 event. Content is immutable for such a pair.
func sameFollowListVersion(eventID nostr.ID, createdAt nostr.Timestamp, list reputation.FollowList) bool {
	return eventID == list.EventID && createdAt == list.CreatedAt
}

func receiptMatchesFollowList(receipt followReceipt, list reputation.FollowList) bool {
	return sameFollowListVersion(receipt.EventID, receipt.CreatedAt, list)
}

// followListSupersedes mirrors replacement semantics used by the graph
// builder: a newer created_at wins, and equal timestamps are broken by the
// lower event ID. A candidate that is not newer must never roll storage back.
func followListSupersedes(candidate, current reputation.FollowList) bool {
	if candidate.CreatedAt != current.CreatedAt {
		return candidate.CreatedAt > current.CreatedAt
	}
	return bytes.Compare(candidate.EventID[:], current.EventID[:]) < 0
}
