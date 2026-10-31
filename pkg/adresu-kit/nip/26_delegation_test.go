package nip

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"fiatjaf.com/nostr"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

func signDelegation(t *testing.T, delegatorSK nostr.SecretKey, delegateePubKey, conditions string) string {
	t.Helper()

	privateKey, _ := btcec.PrivKeyFromBytes(delegatorSK[:])

	token := fmt.Sprintf("nostr:delegation:%s:%s", delegateePubKey, conditions)
	hash := sha256.Sum256([]byte(token))
	sig, err := schnorr.Sign(privateKey, hash[:])
	if err != nil {
		t.Fatalf("sign delegation token: %v", err)
	}
	return hex.EncodeToString(sig.Serialize())
}

func delegatedEvent(t *testing.T, delegatorSK, delegateeSK nostr.SecretKey, conditions string, kind nostr.Kind, createdAt int64) *nostr.Event {
	t.Helper()

	delegatorPubKey := delegatorSK.Public()
	delegateePubKey := delegateeSK.Public()

	event := &nostr.Event{
		Kind:      kind,
		CreatedAt: nostr.Timestamp(createdAt),
		Content:   "delegated event",
		Tags: nostr.Tags{
			{"delegation", delegatorPubKey.Hex(), conditions, signDelegation(t, delegatorSK, delegateePubKey.Hex(), conditions)},
		},
	}
	if err := event.Sign(delegateeSK); err != nil {
		t.Fatalf("sign event: %v", err)
	}
	return event
}

// mixedCaseHexSpelling returns a non-canonical spelling of a lowercase hex
// string, so tests can model a wire pubkey that is not merely lowercased.
func mixedCaseHexSpelling(hexStr string) string {
	var b strings.Builder
	b.Grow(len(hexStr))
	changed := false
	for i := 0; i < len(hexStr); i++ {
		c := hexStr[i]
		if i%2 == 0 && c >= 'a' && c <= 'f' {
			b.WriteByte(c - 'a' + 'A')
			changed = true
			continue
		}
		b.WriteByte(c)
	}
	if !changed && len(hexStr) > 0 {
		return strings.ToUpper(hexStr[:1]) + hexStr[1:]
	}
	return b.String()
}

func TestValidateDelegationAcceptsValidDelegation(t *testing.T) {
	delegatorSK := nostr.Generate()
	delegatorPubKey := delegatorSK.Public()
	delegateeSK := nostr.Generate()

	conditions := "kind=1&created_at>100&created_at<2000"
	event := delegatedEvent(t, delegatorSK, delegateeSK, conditions, nostr.KindTextNote, 500)

	got, err := ValidateDelegation(context.Background(), event)
	if err != nil {
		t.Fatalf("ValidateDelegation: %v", err)
	}
	if got != delegatorPubKey.Hex() {
		t.Fatalf("delegator = %q, want %q", got, delegatorPubKey.Hex())
	}
}

// TestValidateDelegationHonorsWirePubKeySpelling is the regression for the
// typed-event migration: the delegation token is hashed over the delegatee
// pubkey exactly as the delegator signed it. The token here is signed over a
// mixed-case spelling that only exists on the wire, so it can verify only when
// ValidateDelegation reads the recorded provenance instead of the typed
// event.PubKey. Merely re-encoding a lowercase-signed token cannot pass this.
func TestValidateDelegationHonorsWirePubKeySpelling(t *testing.T) {
	delegatorSK := nostr.Generate()
	delegatorPubKey := delegatorSK.Public()
	delegateeSK := nostr.Generate()

	wirePubKey := mixedCaseHexSpelling(delegateeSK.Public().Hex())
	if wirePubKey == delegateeSK.Public().Hex() {
		t.Fatalf("test spelling %q is not distinct from canonical lowercase hex", wirePubKey)
	}

	conditions := "kind=1"
	event := &nostr.Event{
		Kind:      nostr.KindTextNote,
		CreatedAt: nostr.Timestamp(500),
		Content:   "delegated event",
		Tags: nostr.Tags{
			{"delegation", delegatorPubKey.Hex(), conditions, signDelegation(t, delegatorSK, wirePubKey, conditions)},
		},
	}
	if err := event.Sign(delegateeSK); err != nil {
		t.Fatalf("sign event: %v", err)
	}

	ctx := WithWirePubKey(context.Background(), event, wirePubKey)
	got, err := ValidateDelegation(ctx, event)
	if err != nil {
		t.Fatalf("ValidateDelegation rejected a tag signed over the recorded wire spelling: %v", err)
	}
	if got != delegatorPubKey.Hex() {
		t.Fatalf("delegator = %q, want %q", got, delegatorPubKey.Hex())
	}

	// Without the provenance the only spelling left is the canonical
	// lowercase hex, which must not verify this token.
	if _, err := ValidateDelegation(context.Background(), event); err == nil {
		t.Fatal("ValidateDelegation verified a token that was not hashed over the lowercase pubkey")
	}
}

func TestValidateDelegationAllowsAnyListedKind(t *testing.T) {
	delegatorSK := nostr.Generate()
	delegateeSK := nostr.Generate()

	event := delegatedEvent(t, delegatorSK, delegateeSK, "kind=0&kind=1", nostr.KindTextNote, 500)
	if _, err := ValidateDelegation(context.Background(), event); err != nil {
		t.Fatalf("ValidateDelegation rejected an event matching one of the listed kinds: %v", err)
	}
}

func TestValidateDelegationEnforcesEveryRepeatedCondition(t *testing.T) {
	delegatorSK := nostr.Generate()
	delegateeSK := nostr.Generate()

	// Both lower bounds must hold; only checking the first one lets created_at=1500 through.
	conditions := "kind=1&created_at>1000&created_at>2000"
	event := delegatedEvent(t, delegatorSK, delegateeSK, conditions, nostr.KindTextNote, 1500)

	if _, err := ValidateDelegation(context.Background(), event); err == nil {
		t.Fatal("ValidateDelegation accepted an event that violates the second created_at> condition")
	}
}

func TestValidateDelegationRejectsUnsupportedConditions(t *testing.T) {
	delegatorSK := nostr.Generate()
	delegateeSK := nostr.Generate()

	conditions := "kind=1&expires_at=999"
	event := delegatedEvent(t, delegatorSK, delegateeSK, conditions, nostr.KindTextNote, 500)

	if _, err := ValidateDelegation(context.Background(), event); err == nil {
		t.Fatal("ValidateDelegation accepted a delegation with a condition it cannot enforce")
	}
}

func TestValidateDelegationRejectsConditionViolations(t *testing.T) {
	delegatorSK := nostr.Generate()
	delegateeSK := nostr.Generate()

	tests := []struct {
		name       string
		conditions string
		kind       nostr.Kind
		createdAt  int64
	}{
		{"wrong kind", "kind=1", nostr.KindTextNote + 1, 500},
		{"created_at equal to lower bound", "created_at>500", nostr.KindTextNote, 500},
		{"created_at equal to upper bound", "created_at<500", nostr.KindTextNote, 500},
		{"created_at above upper bound", "created_at<500", nostr.KindTextNote, 501},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := delegatedEvent(t, delegatorSK, delegateeSK, tt.conditions, tt.kind, tt.createdAt)
			if _, err := ValidateDelegation(context.Background(), event); err == nil {
				t.Fatalf("ValidateDelegation accepted event violating %q", tt.conditions)
			}
		})
	}
}

func TestValidateDelegationRejectsOutOfRangeKindCondition(t *testing.T) {
	delegatorSK := nostr.Generate()
	delegateeSK := nostr.Generate()

	// 65537 would wrap to kind 1 if the condition were narrowed to the event
	// kind's width after parsing.
	event := delegatedEvent(t, delegatorSK, delegateeSK, "kind=65537", nostr.KindTextNote, 500)

	if _, err := ValidateDelegation(context.Background(), event); err == nil {
		t.Fatal("ValidateDelegation accepted a kind condition that wraps onto the event kind")
	}
}

func TestValidateDelegationRejectsInvalidSignature(t *testing.T) {
	delegatorSK := nostr.Generate()
	delegateeSK := nostr.Generate()
	delegateePubKey := delegateeSK.Public()

	conditions := "kind=1"
	event := delegatedEvent(t, delegatorSK, delegateeSK, conditions, nostr.KindTextNote, 500)
	event.Tags[0][3] = signDelegation(t, nostr.Generate(), delegateePubKey.Hex(), conditions)

	if _, err := ValidateDelegation(context.Background(), event); err == nil {
		t.Fatal("ValidateDelegation accepted a token signed by the wrong key")
	}
}

func TestValidateDelegationRequiresTag(t *testing.T) {
	event := &nostr.Event{Kind: nostr.KindTextNote, CreatedAt: nostr.Timestamp(500)}
	event.PubKey = nostr.Generate().Public()

	if _, err := ValidateDelegation(context.Background(), event); err == nil {
		t.Fatal("ValidateDelegation accepted an event without a delegation tag")
	}
}

func TestValidateDelegationRejectsNilEvent(t *testing.T) {
	if _, err := ValidateDelegation(context.Background(), nil); err == nil {
		t.Fatal("ValidateDelegation accepted a nil event")
	}
}

func TestValidateDelegationTagValidatesTheGivenTag(t *testing.T) {
	delegatorSK := nostr.Generate()
	delegatorPubKey := delegatorSK.Public()
	delegateeSK := nostr.Generate()
	delegateePubKey := delegateeSK.Public()

	// The first tag is honoured, the second one is validly signed but its
	// created_at condition is not satisfied by this event.
	event := &nostr.Event{
		Kind:      nostr.KindTextNote,
		CreatedAt: nostr.Timestamp(500),
		Content:   "delegated event",
		Tags: nostr.Tags{
			{"delegation", delegatorPubKey.Hex(), "kind=1", signDelegation(t, delegatorSK, delegateePubKey.Hex(), "kind=1")},
			{"delegation", delegatorPubKey.Hex(), "created_at>9999", signDelegation(t, delegatorSK, delegateePubKey.Hex(), "created_at>9999")},
		},
	}
	if err := event.Sign(delegateeSK); err != nil {
		t.Fatalf("sign event: %v", err)
	}

	if _, err := ValidateDelegation(context.Background(), event); err != nil {
		t.Fatalf("ValidateDelegation rejected the valid first tag: %v", err)
	}
	if _, err := ValidateDelegationTag(context.Background(), event, event.Tags[1]); err == nil {
		t.Fatal("ValidateDelegationTag ignored the tag it was given")
	}
	notDelegation := append(nostr.Tag(nil), event.Tags[0]...)
	notDelegation[0] = "other"
	if _, err := ValidateDelegationTag(context.Background(), event, notDelegation); err == nil {
		t.Fatal("ValidateDelegationTag accepted a tag with the wrong name")
	}
}
