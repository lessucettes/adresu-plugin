package nip

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/nbd-wtf/go-nostr"
)

func signDelegation(t *testing.T, delegatorSK, delegateePubKey, conditions string) string {
	t.Helper()

	keyBytes, err := hex.DecodeString(delegatorSK)
	if err != nil {
		t.Fatalf("decode delegator key: %v", err)
	}
	privateKey, _ := btcec.PrivKeyFromBytes(keyBytes)

	token := fmt.Sprintf("nostr:delegation:%s:%s", delegateePubKey, conditions)
	hash := sha256.Sum256([]byte(token))
	sig, err := schnorr.Sign(privateKey, hash[:])
	if err != nil {
		t.Fatalf("sign delegation token: %v", err)
	}
	return hex.EncodeToString(sig.Serialize())
}

func delegatedEvent(t *testing.T, delegatorSK, delegateeSK, conditions string, kind int, createdAt int64) *nostr.Event {
	t.Helper()

	delegatorPubKey, err := nostr.GetPublicKey(delegatorSK)
	if err != nil {
		t.Fatalf("delegator pubkey: %v", err)
	}
	delegateePubKey, err := nostr.GetPublicKey(delegateeSK)
	if err != nil {
		t.Fatalf("delegatee pubkey: %v", err)
	}

	event := &nostr.Event{
		Kind:      kind,
		CreatedAt: nostr.Timestamp(createdAt),
		Content:   "delegated event",
		Tags: nostr.Tags{
			{"delegation", delegatorPubKey, conditions, signDelegation(t, delegatorSK, delegateePubKey, conditions)},
		},
	}
	if err := event.Sign(delegateeSK); err != nil {
		t.Fatalf("sign event: %v", err)
	}
	return event
}

func TestValidateDelegationAcceptsValidDelegation(t *testing.T) {
	delegatorSK := nostr.GeneratePrivateKey()
	delegatorPubKey, err := nostr.GetPublicKey(delegatorSK)
	if err != nil {
		t.Fatalf("delegator pubkey: %v", err)
	}
	delegateeSK := nostr.GeneratePrivateKey()

	conditions := "kind=1&created_at>100&created_at<2000"
	event := delegatedEvent(t, delegatorSK, delegateeSK, conditions, nostr.KindTextNote, 500)

	got, err := ValidateDelegation(event)
	if err != nil {
		t.Fatalf("ValidateDelegation: %v", err)
	}
	if got != delegatorPubKey {
		t.Fatalf("delegator = %q, want %q", got, delegatorPubKey)
	}
}

func TestValidateDelegationAllowsAnyListedKind(t *testing.T) {
	delegatorSK := nostr.GeneratePrivateKey()
	delegateeSK := nostr.GeneratePrivateKey()

	event := delegatedEvent(t, delegatorSK, delegateeSK, "kind=0&kind=1", nostr.KindTextNote, 500)
	if _, err := ValidateDelegation(event); err != nil {
		t.Fatalf("ValidateDelegation rejected an event matching one of the listed kinds: %v", err)
	}
}

func TestValidateDelegationEnforcesEveryRepeatedCondition(t *testing.T) {
	delegatorSK := nostr.GeneratePrivateKey()
	delegateeSK := nostr.GeneratePrivateKey()

	// Both lower bounds must hold; only checking the first one lets created_at=1500 through.
	conditions := "kind=1&created_at>1000&created_at>2000"
	event := delegatedEvent(t, delegatorSK, delegateeSK, conditions, nostr.KindTextNote, 1500)

	if _, err := ValidateDelegation(event); err == nil {
		t.Fatal("ValidateDelegation accepted an event that violates the second created_at> condition")
	}
}

func TestValidateDelegationRejectsUnsupportedConditions(t *testing.T) {
	delegatorSK := nostr.GeneratePrivateKey()
	delegateeSK := nostr.GeneratePrivateKey()

	conditions := "kind=1&expires_at=999"
	event := delegatedEvent(t, delegatorSK, delegateeSK, conditions, nostr.KindTextNote, 500)

	if _, err := ValidateDelegation(event); err == nil {
		t.Fatal("ValidateDelegation accepted a delegation with a condition it cannot enforce")
	}
}

func TestValidateDelegationRejectsConditionViolations(t *testing.T) {
	delegatorSK := nostr.GeneratePrivateKey()
	delegateeSK := nostr.GeneratePrivateKey()

	tests := []struct {
		name       string
		conditions string
		kind       int
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
			if _, err := ValidateDelegation(event); err == nil {
				t.Fatalf("ValidateDelegation accepted event violating %q", tt.conditions)
			}
		})
	}
}

func TestValidateDelegationRejectsInvalidSignature(t *testing.T) {
	delegatorSK := nostr.GeneratePrivateKey()
	delegateeSK := nostr.GeneratePrivateKey()
	delegateePubKey, err := nostr.GetPublicKey(delegateeSK)
	if err != nil {
		t.Fatalf("delegatee pubkey: %v", err)
	}

	conditions := "kind=1"
	event := delegatedEvent(t, delegatorSK, delegateeSK, conditions, nostr.KindTextNote, 500)
	event.Tags[0][3] = signDelegation(t, nostr.GeneratePrivateKey(), delegateePubKey, conditions)

	if _, err := ValidateDelegation(event); err == nil {
		t.Fatal("ValidateDelegation accepted a token signed by the wrong key")
	}
}

func TestValidateDelegationRequiresTag(t *testing.T) {
	event := &nostr.Event{Kind: nostr.KindTextNote, CreatedAt: nostr.Timestamp(500)}
	event.PubKey = newPubKey(t)

	if _, err := ValidateDelegation(event); err == nil {
		t.Fatal("ValidateDelegation accepted an event without a delegation tag")
	}
}

func TestValidateDelegationRejectsNilEvent(t *testing.T) {
	if _, err := ValidateDelegation(nil); err == nil {
		t.Fatal("ValidateDelegation accepted a nil event")
	}
}

func TestValidateDelegationTagValidatesTheGivenTag(t *testing.T) {
	delegatorSK := nostr.GeneratePrivateKey()
	delegatorPubKey, err := nostr.GetPublicKey(delegatorSK)
	if err != nil {
		t.Fatalf("delegator pubkey: %v", err)
	}
	delegateeSK := nostr.GeneratePrivateKey()
	delegateePubKey, err := nostr.GetPublicKey(delegateeSK)
	if err != nil {
		t.Fatalf("delegatee pubkey: %v", err)
	}

	// The first tag is honoured, the second one is validly signed but its
	// created_at condition is not satisfied by this event.
	event := &nostr.Event{
		Kind:      nostr.KindTextNote,
		CreatedAt: nostr.Timestamp(500),
		Content:   "delegated event",
		Tags: nostr.Tags{
			{"delegation", delegatorPubKey, "kind=1", signDelegation(t, delegatorSK, delegateePubKey, "kind=1")},
			{"delegation", delegatorPubKey, "created_at>9999", signDelegation(t, delegatorSK, delegateePubKey, "created_at>9999")},
		},
	}
	if err := event.Sign(delegateeSK); err != nil {
		t.Fatalf("sign event: %v", err)
	}

	if _, err := ValidateDelegation(event); err != nil {
		t.Fatalf("ValidateDelegation rejected the valid first tag: %v", err)
	}
	if _, err := ValidateDelegationTag(event, event.Tags[1]); err == nil {
		t.Fatal("ValidateDelegationTag ignored the tag it was given")
	}
	notDelegation := append(nostr.Tag(nil), event.Tags[0]...)
	notDelegation[0] = "other"
	if _, err := ValidateDelegationTag(event, notDelegation); err == nil {
		t.Fatal("ValidateDelegationTag accepted a tag with the wrong name")
	}
}

func newPubKey(t *testing.T) string {
	t.Helper()
	pubkey, err := nostr.GetPublicKey(nostr.GeneratePrivateKey())
	if err != nil {
		t.Fatalf("pubkey: %v", err)
	}
	return pubkey
}
