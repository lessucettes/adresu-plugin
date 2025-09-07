package policy

import (
	"adresu-plugin/config"
	"adresu-plugin/testutils"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/nbd-wtf/go-nostr"
)

// newFilter creates a filter with the given store and NIP-26 flag.
func newFilter(store *testutils.MockStore, checkNIP26 bool) *BannedAuthorFilter {
	cfg := &config.BannedAuthorFilterConfig{CheckNIP26: checkNIP26}
	return NewBannedAuthorFilter(store, cfg)
}

// makeKey deterministically generates a keypair from a label.
func makeKey(label string) (*btcec.PrivateKey, string) {
	sum := sha256.Sum256([]byte(label))
	priv, _ := btcec.PrivKeyFromBytes(sum[:])
	xonly := schnorr.SerializePubKey(priv.PubKey())
	return priv, hex.EncodeToString(xonly)
}

// makeDelegationTag builds a valid NIP-26 delegation tag.
func makeDelegationTag(t *testing.T, delegatorPriv *btcec.PrivateKey, delegateePubKey, conditions string) nostr.Tag {
	t.Helper()
	token := fmt.Sprintf("nostr:delegation:%s:%s", delegateePubKey, conditions)
	h := sha256.Sum256([]byte(token))
	sig, err := schnorr.Sign(delegatorPriv, h[:])
	if err != nil {
		t.Fatalf("schnorr.Sign failed: %v", err)
	}
	delegatorX := hex.EncodeToString(schnorr.SerializePubKey(delegatorPriv.PubKey()))
	return nostr.Tag{"delegation", delegatorX, conditions, hex.EncodeToString(sig.Serialize())}
}

func TestBannedAuthorFilter_Rejects(t *testing.T) {
	st := testutils.NewMockStore()
	f := newFilter(st, false)

	// Ban the author (store keys are case-insensitive in the filter).
	_ = st.BanAuthor(context.Background(), strings.ToLower(testutils.TestPubKey), time.Hour)

	ev := testutils.MakeTextNote(testutils.TestPubKey, "hello", time.Now())
	res := f.Check(context.Background(), ev, "ip1")
	if res == nil || res.Action != "reject" {
		t.Fatalf("expected reject, got %#v", res)
	}
}

func TestBannedAuthorFilterAuthorNotBanned_Accepts(t *testing.T) {
	st := testutils.NewMockStore()
	f := newFilter(st, false)

	ev := testutils.MakeTextNote(testutils.TestPubKey, "hi", time.Now())
	res := f.Check(context.Background(), ev, "ip1")
	if res == nil || res.Action != "accept" {
		t.Fatalf("expected accept, got %#v", res)
	}
}

func TestBannedAuthorFilterIsBanned_CaseInsensitive(t *testing.T) {
	st := testutils.NewMockStore()
	f := newFilter(st, false)

	// Store contains lowercase key...
	_ = st.BanAuthor(context.Background(), strings.ToLower(testutils.TestPubKey), time.Hour)
	// ...but event uses uppercase key → should still be rejected.
	ev := testutils.MakeTextNote(strings.ToUpper(testutils.TestPubKey), "case test", time.Now())

	res := f.Check(context.Background(), ev, "ip1")
	if res == nil || res.Action != "reject" {
		t.Fatalf("expected reject (case-insensitive), got %#v", res)
	}
}

func TestBannedAuthorFilterDelegation_Ignored_WhenDisabled(t *testing.T) {
	st := testutils.NewMockStore()
	f := newFilter(st, false) // CheckNIP26 disabled

	delegatorPriv, delegator := makeKey("carol-delegator")
	_, delegatee := makeKey("carol-signer")

	// Even though delegator is banned, NIP-26 check is disabled → event accepted.
	_ = st.BanAuthor(context.Background(), strings.ToLower(delegator), time.Hour)

	now := time.Unix(1_700_000_100, 0)
	// Use URL-encoded operators and '=' to separate key and value.
	conds := "kind=1&created_at%3E=1699999999&created_at%3C=1999999999"
	tag := makeDelegationTag(t, delegatorPriv, delegatee, conds)

	ev := testutils.MakeEvent(1, "msg", delegatee, now, tag)
	res := f.Check(context.Background(), ev, "ip1")
	if res == nil || res.Action != "accept" {
		t.Fatalf("expected accept when CheckNIP26=false, got %#v", res)
	}
}

func TestBannedAuthorFilterDelegation_Valid_BannedDelegator_Rejects(t *testing.T) {
	st := testutils.NewMockStore()
	f := newFilter(st, true)

	delegatorPriv, delegator := makeKey("dave-delegator")
	_, delegatee := makeKey("dave-signer")

	// Delegator is banned → valid delegation should be rejected.
	_ = st.BanAuthor(context.Background(), strings.ToLower(delegator), time.Hour)

	now := time.Unix(1_700_000_100, 0)
	conds := "kind=1&created_at%3E=1699999999&created_at%3C=1999999999"
	tag := makeDelegationTag(t, delegatorPriv, delegatee, conds)

	ev := testutils.MakeEvent(1, "msg", delegatee, now, tag)
	res := f.Check(context.Background(), ev, "ip1")
	if res == nil || res.Action != "reject" {
		t.Fatalf("expected reject (delegator banned), got %#v", res)
	}
}

func TestBannedAuthorFilterDelegation_InvalidSignature_Rejects(t *testing.T) {
	st := testutils.NewMockStore()
	f := newFilter(st, true)

	delegatorPriv, _ := makeKey("erin-delegator")
	_, delegateeReal := makeKey("erin-signer-real")
	_, delegateeOther := makeKey("erin-signer-other")

	now := time.Unix(1_700_000_100, 0)
	conds := "kind=1&created_at%3E=1699999999&created_at%3C=1999999999"

	// Delegation signed for delegateeOther, but event comes from delegateeReal → invalid signature.
	tag := makeDelegationTag(t, delegatorPriv, delegateeOther, conds)
	ev := testutils.MakeEvent(1, "msg", delegateeReal, now, tag)

	res := f.Check(context.Background(), ev, "ip1")
	if res == nil || res.Action != "reject" {
		t.Fatalf("expected reject (invalid delegation signature), got %#v", res)
	}
}

func TestBannedAuthorFilterValidateDelegationConditions_MultiKind_TimeWindows(t *testing.T) {
	st := testutils.NewMockStore()
	f := newFilter(st, true)

	_, delegatee := makeKey("frank-signer")
	// Operators must be URL-encoded and value separated with '='.
	conds := "kind=7&kind=1&created_at%3E=1690000000&created_at%3C=1990000000"

	// kind=1 is allowed and created_at is within window
	ev1 := testutils.MakeEvent(1, "ok", delegatee, time.Unix(1_700_000_100, 0))
	if err := f.validateDelegationConditions(ev1, conds); err != nil {
		t.Fatalf("conditions should pass, got err: %v", err)
	}

	// kind=42 is not in allowed list
	ev2 := testutils.MakeEvent(42, "bad-kind", delegatee, time.Unix(1_700_000_100, 0))
	if err := f.validateDelegationConditions(ev2, conds); err == nil {
		t.Fatalf("conditions should fail for kind=42")
	}

	// created_at before lower bound
	ev3 := testutils.MakeEvent(1, "too-old", delegatee, time.Unix(1_600_000_000, 0))
	if err := f.validateDelegationConditions(ev3, conds); err == nil {
		t.Fatalf("conditions should fail for created_at below bound")
	}
}

func TestBannedAuthorFilterValidateDelegationConditions_PlusSign_Safe(t *testing.T) {
	st := testutils.NewMockStore()
	f := newFilter(st, true)

	_, delegatee := makeKey("grace-signer")

	// Unknown key with plus signs is ignored; time conditions still apply.
	conds := "kind=1&note=foo+bar+baz&created_at%3E=1690000000&created_at%3C=1990000000"
	ev := testutils.MakeEvent(1, "plus", delegatee, time.Unix(1_700_000_000, 0))

	if err := f.validateDelegationConditions(ev, conds); err != nil {
		t.Fatalf("conditions with plus should pass (unknown keys ignored), got err: %v", err)
	}
}

// --- singleflight stress test ---

func TestBannedAuthorFilterIsBanned_Singleflight_DeduplicatesConcurrentMisses(t *testing.T) {
	st := testutils.NewMockStore()
	f := newFilter(st, false)

	// Use a pubkey that is not banned; the first lookup should miss and hit the store,
	// and concurrent lookups should be deduplicated by singleflight.
	pk := testutils.TestPubKey

	const goroutines = 32
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			<-start
			ev := testutils.MakeTextNote(pk, "concurrent", time.Now())
			_ = f.Check(context.Background(), ev, "ipX")
		}()
	}

	// Release all goroutines at once to maximize contention.
	close(start)
	wg.Wait()

	// With singleflight + LRU, IsAuthorBanned should have been called at most a couple of times
	// (allowing 1-2 to account for narrow races), but certainly not once per goroutine.
	if calls := st.Calls(); calls > 2 {
		t.Fatalf("expected store calls <= 2, got %d (singleflight not effective?)", calls)
	}

	// A second wave should be pure cache hits → no additional store calls.
	prev := st.Calls()
	for i := 0; i < goroutines; i++ {
		ev := testutils.MakeTextNote(pk, "cache-hit", time.Now())
		_ = f.Check(context.Background(), ev, "ipY")
	}
	if calls := st.Calls(); calls != prev {
		t.Fatalf("expected no extra store calls on cache hits, got %d -> %d", prev, calls)
	}
}
