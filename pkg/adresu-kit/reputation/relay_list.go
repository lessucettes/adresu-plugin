package reputation

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"fiatjaf.com/nostr"
	"github.com/lessucettes/adresu-plugin/pkg/adresu-kit/nip"
)

// RelayList is the verified NIP-65 write-relay metadata of one author. An
// empty WriteRelays slice is a real metadata event without usable write
// relays, not a failed lookup.
type RelayList struct {
	Author      nostr.PubKey
	EventID     nostr.ID
	CreatedAt   nostr.Timestamp
	FetchedAt   time.Time
	WriteRelays []string
}

// Bounds for untrusted NIP-65 metadata. Four write relays per author are
// enough for a targeted fallback; more would let one author multiply the
// collector's connection fan-out.
const (
	maxRelayListBytes        = 2 << 20
	maxRelayListTags         = 32
	maxRelayListTotalTags    = 128
	maxRelayListWriteRelays  = 4
	maxRelayListURLBytes     = 2048
	maxRelayListFutureSkew   = 5 * time.Minute
	maxRelayListSignatureHex = 128
)

// ParseRelayList validates a signed kind-10002 event and extracts its write
// relay URLs. Read-only markers are excluded. The event is verified with the
// same strict canonical encoding as follow lists, so relay URLs from an
// unverified or malformed metadata event are never returned.
func ParseRelayList(ctx context.Context, raw []byte, now time.Time) (RelayList, error) {
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
		return RelayList{}, err
	}
	if len(raw) > maxRelayListBytes {
		return RelayList{}, fmt.Errorf("relay list exceeds the metadata byte bound")
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return RelayList{}, fmt.Errorf("decode relay list: %w", err)
	}
	if wire.Kind != uint16(nostr.KindRelayListMetadata) || len(wire.Tags) > maxRelayListTotalTags {
		return RelayList{}, fmt.Errorf("invalid relay-list kind or tag count")
	}
	relayTags := 0
	for _, tag := range wire.Tags {
		if len(tag) > 0 && tag[0] == "r" {
			relayTags++
		}
	}
	if relayTags > maxRelayListTags {
		return RelayList{}, fmt.Errorf("relay list exceeds the relay-tag bound")
	}
	if int64(wire.CreatedAt) < 0 || int64(wire.CreatedAt) > now.Add(maxRelayListFutureSkew).Unix() {
		return RelayList{}, fmt.Errorf("relay-list timestamp is out of range")
	}
	if !nostr.IsValid32ByteHex(strings.ToLower(wire.ID)) ||
		!nostr.IsValid32ByteHex(strings.ToLower(wire.PubKey)) ||
		len(wire.Sig) != maxRelayListSignatureHex {
		return RelayList{}, fmt.Errorf("invalid relay-list identifiers or signature length")
	}
	id, err := nostr.IDFromHex(wire.ID)
	if err != nil {
		return RelayList{}, err
	}
	pk, err := nostr.PubKeyFromHex(wire.PubKey)
	if err != nil {
		return RelayList{}, err
	}
	var sig [64]byte
	if _, err := hex.Decode(sig[:], []byte(wire.Sig)); err != nil {
		return RelayList{}, fmt.Errorf("decode relay-list signature: %w", err)
	}
	event := nostr.Event{
		ID: id, PubKey: pk, CreatedAt: wire.CreatedAt,
		Kind: nostr.KindRelayListMetadata, Tags: wire.Tags,
		Content: wire.Content, Sig: sig,
	}
	ctx = nip.WithWirePubKey(ctx, &event, wire.PubKey)
	if event.ID != nip.CanonicalEventID(ctx, &event) {
		return RelayList{}, fmt.Errorf("relay-list ID does not match its body")
	}
	valid, err := nip.CheckEventSignature(ctx, &event)
	if err != nil || !valid {
		return RelayList{}, fmt.Errorf("invalid relay-list signature")
	}
	seen := make(map[string]struct{}, maxRelayListWriteRelays)
	writeRelays := make([]string, 0, maxRelayListWriteRelays)
	for _, tag := range wire.Tags {
		if len(tag) < 2 || tag[0] != "r" {
			continue
		}
		if len(tag) > 2 {
			// Absent marker means read and write. A read-only or unknown
			// marker must never become a write target.
			if tag[2] != "" && tag[2] != "write" {
				continue
			}
		}
		relay, ok := parseRelayListURL(tag[1])
		if !ok {
			continue
		}
		if _, duplicate := seen[relay]; duplicate {
			continue
		}
		seen[relay] = struct{}{}
		writeRelays = append(writeRelays, relay)
		if len(writeRelays) == maxRelayListWriteRelays {
			break
		}
	}
	return RelayList{
		Author: pk, EventID: id, CreatedAt: wire.CreatedAt,
		FetchedAt: now.UTC(), WriteRelays: writeRelays,
	}, nil
}

// parseRelayListURL accepts only secure WebSocket relay endpoints. Address
// based SSRF checks happen again at dial time; this only removes values that
// can never be a legitimate discovered relay.
func parseRelayListURL(raw string) (string, bool) {
	if raw == "" || len(raw) > maxRelayListURLBytes || strings.ContainsAny(raw, " 	\r\n") {
		return "", false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "wss" || parsed.Opaque != "" {
		return "", false
	}
	if parsed.Hostname() == "" || parsed.User != nil {
		return "", false
	}
	if parsed.Fragment != "" || strings.Contains(raw, "#") {
		return "", false
	}
	relay := parsed.String()
	if len(relay) > maxRelayListURLBytes {
		return "", false
	}
	return relay, true
}

// newerRelayList applies replaceable-event ordering: newest created_at wins,
// then the lexicographically lower event id.
func newerRelayList(a, b RelayList) bool {
	return a.CreatedAt > b.CreatedAt ||
		(a.CreatedAt == b.CreatedAt && bytes.Compare(a.EventID[:], b.EventID[:]) < 0)
}
