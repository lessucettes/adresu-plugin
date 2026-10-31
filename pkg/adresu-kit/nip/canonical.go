package nip

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"strings"

	"fiatjaf.com/nostr"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

const lowerHexDigits = "0123456789abcdef"

// wirePubKeyContextKey keys the per-event wire pubkey spelling recorded by
// WithWirePubKey.
type wirePubKeyContextKey struct{}

// wirePubKeyProvenance links one raw wire pubkey spelling to the exact decoded
// event pointer and key bytes it belongs to. Entries form a stack so a context
// can carry provenance for more than one event.
type wirePubKeyProvenance struct {
	event *nostr.Event
	wire  string
	key   nostr.PubKey
	prev  *wirePubKeyProvenance
}

// WithWirePubKey records the pubkey spelling from the raw wire event for ctx.
//
// strfry hashes the original JSON "pubkey" string verbatim, so a client that
// signed an uppercase (or mixed-case) spelling has a valid event whose ID only
// recomputes from that exact spelling. The typed event no longer carries it;
// this provenance survives until the event is processed. The override is only
// recorded when pubkey decodes to the event's own key and differs from its
// canonical lowercase hex, otherwise ctx is returned unchanged. Creation and
// lookup are bound to the event pointer, so copies and other events are never
// affected.
func WithWirePubKey(ctx context.Context, event *nostr.Event, pubkey string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if event == nil {
		return ctx
	}
	if !nostr.IsValid32ByteHex(strings.ToLower(pubkey)) {
		return ctx
	}
	decoded, err := nostr.PubKeyFromHexCheap(pubkey)
	if err != nil || decoded != event.PubKey {
		return ctx
	}
	if pubkey == decoded.Hex() {
		return ctx
	}
	prev, _ := ctx.Value(wirePubKeyContextKey{}).(*wirePubKeyProvenance)
	return context.WithValue(ctx, wirePubKeyContextKey{}, &wirePubKeyProvenance{
		event: event,
		wire:  pubkey,
		key:   decoded,
		prev:  prev,
	})
}

// wirePubKeyFor returns the recorded spelling for this exact event pointer,
// re-validating it against the event's current key bytes.
func wirePubKeyFor(ctx context.Context, event *nostr.Event) (string, bool) {
	if ctx == nil || event == nil {
		return "", false
	}
	prov, _ := ctx.Value(wirePubKeyContextKey{}).(*wirePubKeyProvenance)
	for p := prov; p != nil; p = p.prev {
		if p.event == event && p.key == event.PubKey && len(p.wire) == 64 {
			return p.wire, true
		}
	}
	return "", false
}

// CanonicalEventID computes the NIP-01 event id from the event body.
//
// The pinned fiatjaf.com/nostr serializer only escapes '"', '\\' and the
// whitespace controls \t, \n and \r; every other byte below 0x20 is written
// raw, which produces an id that no other NIP-01 implementation derives from
// the same event. Strings that trigger that defect (rare control characters in
// the content or tags) go through an explicit canonical encoder here; all
// other events use the library's normal path unchanged.
//
// A wire pubkey spelling recorded with WithWirePubKey for this exact event is
// substituted for the 64 hex pubkey characters, because that is what strfry
// and the signing client hashed. Without such provenance the canonical
// lowercase hex is used.
func CanonicalEventID(ctx context.Context, event *nostr.Event) nostr.ID {
	if event == nil {
		return nostr.ZeroID
	}
	if wire, ok := wirePubKeyFor(ctx, event); ok {
		sum := sha256.Sum256(serializeCanonical(event, wire))
		return nostr.ID(sum)
	}
	if !needsCanonicalSerialization(event) {
		return event.GetID()
	}
	sum := sha256.Sum256(serializeCanonical(event, event.PubKey.Hex()))
	return nostr.ID(sum)
}

// needsCanonicalSerialization reports whether any hashed string contains a
// control byte that the pinned serializer leaves unescaped.
func needsCanonicalSerialization(event *nostr.Event) bool {
	if hasUnescapedControl(event.Content) {
		return true
	}
	for _, tag := range event.Tags {
		for _, value := range tag {
			if hasUnescapedControl(value) {
				return true
			}
		}
	}
	return false
}

func hasUnescapedControl(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 && c != '\t' && c != '\n' && c != '\r' {
			return true
		}
	}
	return false
}

// serializeCanonical repairs only the pinned serializer's unescaped control
// bytes and, when needed, the fixed-width pubkey spelling. The upstream encoder
// still owns the event layout and all other escaping.
// Keep the short \b and \f escapes: equivalent JSON with \u0008 or \u000c
// would hash differently from strfry's canonical serialization.
func serializeCanonical(event *nostr.Event, pubKeyHex string) []byte {
	raw := event.Serialize()
	// Serialize starts with [0,"<64 hex characters>",...]. Both spellings
	// encode the same validated key and have exactly the same width.
	copy(raw[4:68], pubKeyHex)
	dst := make([]byte, 0, len(raw))
	for _, c := range raw {
		switch c {
		case '\b':
			dst = append(dst, '\\', 'b')
		case '\f':
			dst = append(dst, '\\', 'f')
		default:
			if c < 0x20 {
				dst = append(dst, '\\', 'u', '0', '0', lowerHexDigits[c>>4], lowerHexDigits[c&0xf])
			} else {
				dst = append(dst, c)
			}
		}
	}
	return dst
}

// secp256k1Order is the group order n of the secp256k1 curve (big-endian).
// BIP-340 requires a signature's s component to be strictly less than n.
var secp256k1Order = [32]byte{
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
	0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
	0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
}

// CheckEventSignature verifies the event's Schnorr signature against the
// canonical hash of its body. It deliberately ignores the event.ID field:
// callers that need to bind the ID to the body compare CanonicalEventID(ctx, event)
// with event.ID themselves. The signature is checked against the wire pubkey
// spelling recorded for this event, if any, because that is the string the
// author signed over. A nil event or an invalid public key is reported as an
// error; an invalid signature is (false, nil).
//
// The s component is checked against the curve order before parsing. Both the
// pinned library's VerifySignature and btcec's schnorr.ParseSignature accept
// 32-byte s values >= n and silently reduce them modulo n, although BIP-340
// requires s < n; rejecting that non-canonical encoding here keeps the
// verification strict instead of inheriting the reduction.
func CheckEventSignature(ctx context.Context, event *nostr.Event) (bool, error) {
	if event == nil {
		return false, fmt.Errorf("event is nil")
	}
	pubKey, err := schnorr.ParsePubKey(event.PubKey[:])
	if err != nil {
		return false, fmt.Errorf("invalid public key: %w", err)
	}
	if bytes.Compare(event.Sig[32:], secp256k1Order[:]) >= 0 {
		return false, fmt.Errorf("non-canonical signature: s is not less than the secp256k1 order")
	}
	sig, err := schnorr.ParseSignature(event.Sig[:])
	if err != nil {
		return false, fmt.Errorf("invalid signature: %w", err)
	}
	id := CanonicalEventID(ctx, event)
	return sig.Verify(id[:], pubKey), nil
}
