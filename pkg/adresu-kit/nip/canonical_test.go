package nip

import (
	"context"
	"crypto/sha256"
	"strings"
	"testing"

	"fiatjaf.com/nostr"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

func TestCanonicalEventIDEscapesControlCharacters(t *testing.T) {
	pubKey := nostr.KeyOne.Public()
	event := &nostr.Event{
		PubKey:    pubKey,
		CreatedAt: nostr.Timestamp(1700000000),
		Kind:      nostr.KindTextNote,
		Tags: nostr.Tags{
			{"t", "x\x02y"},
			{"note", "a\x01b\x08c\x0cd\x1fe"},
		},
		Content: "a\x01b\x08c\x0cd\x1fe\x1ff\x7f\x00\u2028<&>\"\\\n\t\r",
	}

	// Independent NIP-01 oracle: the exact canonical bytes, written by hand
	// instead of derived from any encoder under test.
	wantBytes := "[0,\"" + pubKey.Hex() + "\",1700000000,1," +
		"[[\"t\",\"x\\u0002y\"],[\"note\",\"a\\u0001b\\bc\\fd\\u001fe\"]]," +
		"\"a\\u0001b\\bc\\fd\\u001fe\\u001ff\u007f\\u0000\u2028<&>\\\"\\\\\\n\\t\\r\"]"
	want := sha256.Sum256([]byte(wantBytes))

	if got := CanonicalEventID(context.Background(), event); got != nostr.ID(want) {
		t.Fatalf("CanonicalEventID = %s, want %s\ncanonical bytes used: %q", got.Hex(), nostr.ID(want).Hex(), wantBytes)
	}
}

func TestCanonicalEventIDUsesLibraryPathForPortableStrings(t *testing.T) {
	pubKey := nostr.KeyOne.Public()
	event := &nostr.Event{
		PubKey:    pubKey,
		CreatedAt: nostr.Timestamp(1700000000),
		Kind:      nostr.KindTextNote,
		Tags:      nostr.Tags{{"t", "x\"y\\z\n"}},
		Content:   "plain \"quoted\" \\ <&>\n\t\r\u2028",
	}

	// Only characters the pinned serializer escapes are present, so the normal
	// upstream path must be used unchanged.
	if got, want := CanonicalEventID(context.Background(), event), event.GetID(); got != want {
		t.Fatalf("CanonicalEventID = %s, library GetID = %s", got.Hex(), want.Hex())
	}

	// The normal path must still be NIP-01 canonical.
	wantBytes := "[0,\"" + pubKey.Hex() + "\",1700000000,1," +
		"[[\"t\",\"x\\\"y\\\\z\\n\"]]," +
		"\"plain \\\"quoted\\\" \\\\ <&>\\n\\t\\r\u2028\"]"
	want := sha256.Sum256([]byte(wantBytes))
	if got := CanonicalEventID(context.Background(), event); got != nostr.ID(want) {
		t.Fatalf("CanonicalEventID = %s, want %s\ncanonical bytes used: %q", got.Hex(), nostr.ID(want).Hex(), wantBytes)
	}
}

func TestCanonicalEventIDHonorsWirePubKeyProvenance(t *testing.T) {
	sk := nostr.KeyOne
	event := &nostr.Event{
		CreatedAt: nostr.Timestamp(7),
		Kind:      nostr.KindTextNote,
		Tags:      nostr.Tags{{"t", "x\x02y"}},
		Content:   "a\x01b",
	}
	event.PubKey = sk.Public()
	wirePubKey := strings.ToUpper(event.PubKey.Hex())

	// strfry hashes the original JSON pubkey string verbatim, so this is the
	// canonical body a client signing an uppercase author produced.
	wantBytes := "[0,\"" + wirePubKey + "\",7,1,[[\"t\",\"x\\u0002y\"]],\"a\\u0001b\"]"
	want := sha256.Sum256([]byte(wantBytes))

	privateKey, _ := btcec.PrivKeyFromBytes(sk[:])
	sig, err := schnorr.Sign(privateKey, want[:])
	if err != nil {
		t.Fatalf("sign uppercase body: %v", err)
	}
	copy(event.Sig[:], sig.Serialize())
	event.ID = nostr.ID(want)

	ctx := WithWirePubKey(context.Background(), event, wirePubKey)
	if got := CanonicalEventID(ctx, event); got != nostr.ID(want) {
		t.Fatalf("CanonicalEventID with provenance = %s, want %s", got.Hex(), nostr.ID(want).Hex())
	}
	ok, err := CheckEventSignature(ctx, event)
	if err != nil {
		t.Fatalf("CheckEventSignature with provenance: %v", err)
	}
	if !ok {
		t.Fatal("CheckEventSignature rejected a signature over the uppercase wire pubkey")
	}
	if ok, err := CheckEventSignature(context.Background(), event); ok || err != nil {
		t.Fatalf("CheckEventSignature without provenance = (%v, %v), want (false, nil)", ok, err)
	}
}

func TestWithWirePubKeyIgnoresInapplicableSpellings(t *testing.T) {
	event := &nostr.Event{PubKey: nostr.KeyOne.Public(), CreatedAt: nostr.Timestamp(1), Kind: nostr.KindTextNote, Content: "plain"}
	lowerID := CanonicalEventID(context.Background(), event)
	otherKey := nostr.Generate().Public().Hex()

	tests := []struct {
		name   string
		pubkey string
	}{
		{"different key", strings.ToUpper(otherKey)},
		{"invalid hex", strings.Repeat("zz", 32)},
		{"wrong length", strings.ToUpper(event.PubKey.Hex())[:63]},
		{"already canonical lowercase", event.PubKey.Hex()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := WithWirePubKey(context.Background(), event, tt.pubkey)
			if got := CanonicalEventID(ctx, event); got != lowerID {
				t.Fatalf("inapplicable pubkey %q changed the canonical ID", tt.pubkey)
			}
		})
	}
}

func TestWirePubKeyProvenanceIsBoundToEventPointerAndKey(t *testing.T) {
	event := &nostr.Event{PubKey: nostr.KeyOne.Public(), CreatedAt: nostr.Timestamp(1), Kind: nostr.KindTextNote, Content: "bound"}
	upper := strings.ToUpper(event.PubKey.Hex())
	ctx := WithWirePubKey(context.Background(), event, upper)
	upperID := CanonicalEventID(ctx, event)
	lowerID := CanonicalEventID(context.Background(), event)
	if upperID == lowerID {
		t.Fatal("provenance did not change the canonical ID for the uppercase wire pubkey")
	}

	copied := *event
	if got := CanonicalEventID(ctx, &copied); got != lowerID {
		t.Fatal("wire pubkey provenance leaked to a copy of the event")
	}

	event.PubKey = nostr.Generate().Public()
	if got := CanonicalEventID(ctx, event); got == upperID {
		t.Fatal("wire pubkey provenance survived a change of the event's key")
	}
}

func TestWithWirePubKeyAccumulatesPerEventProvenance(t *testing.T) {
	plain := func(content string) *nostr.Event {
		return &nostr.Event{PubKey: nostr.KeyOne.Public(), CreatedAt: nostr.Timestamp(1), Kind: nostr.KindTextNote, Content: content}
	}
	first, second := plain("first"), plain("second")
	ctx := WithWirePubKey(context.Background(), first, strings.ToUpper(first.PubKey.Hex()))
	ctx = WithWirePubKey(ctx, second, strings.ToUpper(second.PubKey.Hex()))

	for _, event := range []*nostr.Event{first, second} {
		lower := CanonicalEventID(context.Background(), event)
		if got := CanonicalEventID(ctx, event); got == lower {
			t.Fatalf("provenance was lost for event %q", event.Content)
		}
	}
}

func mustSignCanonically(t *testing.T, event *nostr.Event, sk nostr.SecretKey) {
	t.Helper()

	event.PubKey = sk.Public()
	event.ID = CanonicalEventID(context.Background(), event)
	privateKey, _ := btcec.PrivKeyFromBytes(sk[:])
	sig, err := schnorr.Sign(privateKey, event.ID[:])
	if err != nil {
		t.Fatalf("sign event: %v", err)
	}
	copy(event.Sig[:], sig.Serialize())
}

func TestCheckEventSignatureVerifiesCanonicalID(t *testing.T) {
	event := &nostr.Event{
		CreatedAt: nostr.Timestamp(1),
		Kind:      nostr.KindTextNote,
		Tags:      nostr.Tags{{"t", "x\x02y"}},
		Content:   "signed with a control character: \x01",
	}
	mustSignCanonically(t, event, nostr.KeyOne)

	ok, err := CheckEventSignature(context.Background(), event)
	if err != nil {
		t.Fatalf("CheckEventSignature: %v", err)
	}
	if !ok {
		t.Fatal("CheckEventSignature rejected a valid signature over the canonical event body")
	}

	// The signature covers the body, not the ID field; binding those is a
	// separate check that callers perform by comparing CanonicalEventID.
	event.ID[0] ^= 0xff
	ok, err = CheckEventSignature(context.Background(), event)
	if err != nil {
		t.Fatalf("CheckEventSignature with a mismatched ID: %v", err)
	}
	if !ok {
		t.Fatal("CheckEventSignature let the ID field affect signature validity")
	}
}

func TestCheckEventSignatureRejectsTamperedEvent(t *testing.T) {
	event := &nostr.Event{
		CreatedAt: nostr.Timestamp(1),
		Kind:      nostr.KindTextNote,
		Content:   "original",
	}
	mustSignCanonically(t, event, nostr.KeyOne)
	event.Content = "tampered"

	ok, err := CheckEventSignature(context.Background(), event)
	if err != nil {
		t.Fatalf("CheckEventSignature: %v", err)
	}
	if ok {
		t.Fatal("CheckEventSignature accepted a signature that does not cover the content")
	}
}

func TestCheckEventSignatureRejectsNonCanonicalS(t *testing.T) {
	tests := []struct {
		name string
		s    [32]byte
	}{
		{"curve order", secp256k1Order},
		{"above curve order", func() (s [32]byte) {
			for i := range s {
				s[i] = 0xff
			}
			return s
		}()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := &nostr.Event{
				CreatedAt: nostr.Timestamp(1),
				Kind:      nostr.KindTextNote,
				Content:   "canonicality probe",
			}
			mustSignCanonically(t, event, nostr.KeyOne)
			copy(event.Sig[32:], tt.s[:])

			// BIP-340 requires s < n. The pinned library and btcec's parser
			// silently reduce such values modulo n instead of rejecting them.
			ok, err := CheckEventSignature(context.Background(), event)
			if err == nil {
				t.Fatalf("CheckEventSignature accepted a non-canonical s (ok=%v) without an error", ok)
			}
			if ok {
				t.Fatal("CheckEventSignature accepted a non-canonical s")
			}
		})
	}
}

func TestCheckEventSignatureRejectsUnusableAuthorKey(t *testing.T) {
	if ok, err := CheckEventSignature(context.Background(), nil); err == nil || ok {
		t.Fatal("CheckEventSignature accepted a nil event")
	}

	event := &nostr.Event{Content: "no pubkey"}
	if ok, err := CheckEventSignature(context.Background(), event); err == nil || ok {
		t.Fatal("CheckEventSignature accepted the zero public key")
	}
}
