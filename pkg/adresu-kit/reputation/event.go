package reputation

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"fiatjaf.com/nostr"
	"github.com/lessucettes/adresu-plugin/pkg/adresu-kit/nip"
)

// ParseFollowList validates a wire event before extracting a replacement list.
// It uses the kit's strict canonical signature verification, including the
// original pubkey spelling. Future-dated lists beyond five minutes are refused
// so they cannot pin an author's graph version indefinitely.
func ParseFollowList(ctx context.Context, raw []byte, maxFollows int, now time.Time) (FollowList, error) {
	var wire struct {
		ID        string          `json:"id"`
		PubKey    string          `json:"pubkey"`
		CreatedAt nostr.Timestamp `json:"created_at"`
		Kind      uint16          `json:"kind"`
		Tags      nostr.Tags      `json:"tags"`
		Content   string          `json:"content"`
		Sig       string          `json:"sig"`
	}
	if err := ctx.Err(); err != nil {
		return FollowList{}, err
	}
	if maxFollows <= 0 || len(raw) > 2<<20 {
		return FollowList{}, fmt.Errorf("follow list exceeds resource bounds")
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return FollowList{}, fmt.Errorf("decode follow list: %w", err)
	}
	if wire.Kind != 3 || len(wire.Tags) > maxFollows*2+32 {
		return FollowList{}, fmt.Errorf("invalid follow-list kind or tag count")
	}
	// Bound work before any curve validation, including malformed and repeated
	// p tags that do not increase the number of unique graph targets.
	pTags := 0
	for i, tag := range wire.Tags {
		if i%32 == 0 {
			if err := ctx.Err(); err != nil {
				return FollowList{}, err
			}
		}
		if len(tag) > 0 && tag[0] == "p" {
			pTags++
			if pTags > maxFollows {
				return FollowList{}, fmt.Errorf("follow list exceeds max_follows p-tag budget")
			}
		}
	}
	if int64(wire.CreatedAt) < 0 || int64(wire.CreatedAt) > now.Add(5*time.Minute).Unix() {
		return FollowList{}, fmt.Errorf("follow-list timestamp is out of range")
	}
	if !nostr.IsValid32ByteHex(strings.ToLower(wire.ID)) ||
		!nostr.IsValid32ByteHex(strings.ToLower(wire.PubKey)) || len(wire.Sig) != 128 {
		return FollowList{}, fmt.Errorf("invalid follow-list identifiers or signature length")
	}
	id, err := nostr.IDFromHex(wire.ID)
	if err != nil {
		return FollowList{}, err
	}
	pk, err := nostr.PubKeyFromHex(wire.PubKey)
	if err != nil {
		return FollowList{}, err
	}
	var sig [64]byte
	if _, err := hex.Decode(sig[:], []byte(wire.Sig)); err != nil {
		return FollowList{}, fmt.Errorf("decode follow-list signature: %w", err)
	}
	ev := nostr.Event{ID: id, PubKey: pk, CreatedAt: wire.CreatedAt,
		Kind: 3, Tags: wire.Tags, Content: wire.Content, Sig: sig}
	ctx = nip.WithWirePubKey(ctx, &ev, wire.PubKey)
	if ev.ID != nip.CanonicalEventID(ctx, &ev) {
		return FollowList{}, fmt.Errorf("follow-list ID does not match its body")
	}
	valid, err := nip.CheckEventSignature(ctx, &ev)
	if err != nil || !valid {
		return FollowList{}, fmt.Errorf("invalid follow-list signature")
	}
	seen := make(map[nostr.PubKey]struct{})
	for i, tag := range wire.Tags {
		if i%32 == 0 {
			if err := ctx.Err(); err != nil {
				return FollowList{}, err
			}
		}
		if len(tag) < 2 || tag[0] != "p" {
			continue
		}
		if !nostr.IsValid32ByteHex(strings.ToLower(tag[1])) {
			continue
		}
		target, err := nostr.PubKeyFromHex(tag[1])
		if err != nil || target == pk || target == nostr.ZeroPK {
			continue
		}
		seen[target] = struct{}{}
		if len(seen) > maxFollows {
			return FollowList{}, fmt.Errorf("follow list exceeds max_follows")
		}
	}
	follows := make([]nostr.PubKey, 0, len(seen))
	for target := range seen {
		follows = append(follows, target)
	}
	slices.SortFunc(follows, func(a, b nostr.PubKey) int { return bytes.Compare(a[:], b[:]) })
	return FollowList{Author: pk, EventID: id, CreatedAt: ev.CreatedAt,
		FetchedAt: now.UTC(), Follows: follows}, nil
}
