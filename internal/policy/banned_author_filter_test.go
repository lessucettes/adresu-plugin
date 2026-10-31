package policy

import (
	"context"
	"testing"
	"time"

	"fiatjaf.com/nostr"

	"github.com/lessucettes/adresu-plugin/internal/config"
)

func TestBannedAuthorFilterReflectsExternalBanAndUnban(t *testing.T) {
	s := newTestStore()
	filter, err := NewBannedAuthorFilter(s, &config.BannedAuthorFilterConfig{})
	if err != nil {
		t.Fatalf("NewBannedAuthorFilter: %v", err)
	}

	_, pubkey := newKeyPair(t)
	event := &nostr.Event{Kind: nostr.KindTextNote, PubKey: pubkey}
	ctx := context.Background()

	result, err := filter.Match(ctx, event, nil)
	if err != nil || !result.Allowed {
		t.Fatalf("initial Match = %+v, %v; want allowed", result, err)
	}

	// A moderator ban (or an autoban) mutates the store behind the filter's back.
	if err := s.BanAuthor(ctx, pubkey.Hex(), time.Hour); err != nil {
		t.Fatalf("BanAuthor: %v", err)
	}
	result, err = filter.Match(ctx, event, nil)
	if err != nil {
		t.Fatalf("Match after ban: %v", err)
	}
	if result.Allowed {
		t.Fatal("filter kept allowing the author after the author was banned")
	}

	if err := s.UnbanAuthor(ctx, pubkey.Hex()); err != nil {
		t.Fatalf("UnbanAuthor: %v", err)
	}
	result, err = filter.Match(ctx, event, nil)
	if err != nil {
		t.Fatalf("Match after unban: %v", err)
	}
	if !result.Allowed {
		t.Fatal("filter kept rejecting the author after the author was unbanned")
	}
}

func TestBannedAuthorFilterRejectsBannedAuthor(t *testing.T) {
	s := newTestStore()
	filter, err := NewBannedAuthorFilter(s, &config.BannedAuthorFilterConfig{})
	if err != nil {
		t.Fatalf("NewBannedAuthorFilter: %v", err)
	}

	_, pubkey := newKeyPair(t)
	if err := s.BanAuthor(context.Background(), pubkey.Hex(), time.Hour); err != nil {
		t.Fatalf("BanAuthor: %v", err)
	}

	result, err := filter.Match(context.Background(), &nostr.Event{Kind: nostr.KindTextNote, PubKey: pubkey}, nil)
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if result.Allowed {
		t.Fatal("banned author was allowed")
	}
}

func TestBannedAuthorFilterChecksEveryDelegationTag(t *testing.T) {
	s := newTestStore()
	filter, err := NewBannedAuthorFilter(s, &config.BannedAuthorFilterConfig{CheckNIP26: true})
	if err != nil {
		t.Fatalf("NewBannedAuthorFilter: %v", err)
	}

	otherSK, otherPubKey := newKeyPair(t)
	bannedSK, bannedPubKey := newKeyPair(t)
	delegateeSK, delegateePubKey := newKeyPair(t)
	if err := s.BanAuthor(context.Background(), bannedPubKey.Hex(), time.Hour); err != nil {
		t.Fatalf("BanAuthor: %v", err)
	}

	// NIP-26 delegates one identity, but a client can attach several tags. Only
	// validating the first one hides a delegation from a banned author.
	event := &nostr.Event{
		Kind:      nostr.KindTextNote,
		CreatedAt: nostr.Now(),
		Content:   "delegated",
		Tags: nostr.Tags{
			{"delegation", otherPubKey.Hex(), "", signDelegationToken(t, otherSK, delegateePubKey, "")},
			{"delegation", bannedPubKey.Hex(), "", signDelegationToken(t, bannedSK, delegateePubKey, "")},
		},
	}
	if err := event.Sign(delegateeSK); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	result, err := filter.Match(context.Background(), event, nil)
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if result.Allowed {
		t.Fatal("event delegated by a banned author was allowed because its delegation tag was not the first")
	}
}

func TestBannedAuthorFilterRejectsInvalidLaterDelegationTag(t *testing.T) {
	s := newTestStore()
	filter, err := NewBannedAuthorFilter(s, &config.BannedAuthorFilterConfig{CheckNIP26: true})
	if err != nil {
		t.Fatalf("NewBannedAuthorFilter: %v", err)
	}

	otherSK, otherPubKey := newKeyPair(t)
	delegateeSK, delegateePubKey := newKeyPair(t)

	event := &nostr.Event{
		Kind:      nostr.KindTextNote,
		CreatedAt: nostr.Now(),
		Content:   "delegated",
		Tags: nostr.Tags{
			{"delegation", otherPubKey.Hex(), "", signDelegationToken(t, otherSK, delegateePubKey, "")},
			{"delegation", otherPubKey.Hex(), "kind=1", "not-a-signature"},
		},
	}
	if err := event.Sign(delegateeSK); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	result, err := filter.Match(context.Background(), event, nil)
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if result.Allowed {
		t.Fatal("event with an invalid later delegation tag was allowed")
	}
	event.Tags[1] = nostr.Tag{"delegation"}
	if err := event.Sign(delegateeSK); err != nil {
		t.Fatal(err)
	}
	if result, err := filter.Match(context.Background(), event, nil); err != nil || result.Allowed {
		t.Fatalf("truncated delegation = %+v, %v; want rejection", result, err)
	}
}

func TestBannedAuthorFilterRejectsBannedDelegator(t *testing.T) {
	s := newTestStore()
	filter, err := NewBannedAuthorFilter(s, &config.BannedAuthorFilterConfig{CheckNIP26: true})
	if err != nil {
		t.Fatalf("NewBannedAuthorFilter: %v", err)
	}

	delegatorSK, delegatorPubKey := newKeyPair(t)
	delegateeSK, delegateePubKey := newKeyPair(t)

	conditions := "kind=1"
	token := signDelegationToken(t, delegatorSK, delegateePubKey, conditions)
	event := &nostr.Event{
		Kind:      nostr.KindTextNote,
		CreatedAt: nostr.Now(),
		Content:   "delegated",
		Tags:      nostr.Tags{{"delegation", delegatorPubKey.Hex(), conditions, token}},
	}
	if err := event.Sign(delegateeSK); err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if err := s.BanAuthor(context.Background(), delegatorPubKey.Hex(), time.Hour); err != nil {
		t.Fatalf("BanAuthor: %v", err)
	}

	result, err := filter.Match(context.Background(), event, nil)
	if err != nil {
		t.Fatalf("Match: %v", err)
	}
	if result.Allowed {
		t.Fatal("event delegated by a banned author was allowed")
	}
}
