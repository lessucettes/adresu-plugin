package policy

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"

	"github.com/lessucettes/adresu-plugin/internal/config"
)

func newAutoBanConfig(maxStrikes int) *config.AutoBanFilterConfig {
	return &config.AutoBanFilterConfig{
		Enabled:           true,
		MaxStrikes:        maxStrikes,
		StrikeWindow:      time.Minute,
		BanDuration:       time.Hour,
		StrikesCacheSize:  16,
		CooldownCacheSize: 16,
		CooldownDuration:  time.Minute,
		BanTimeout:        time.Second,
	}
}

func TestAutoBanIgnoresForgedAuthor(t *testing.T) {
	s := newTestStore()
	filter, err := NewAutoBanFilter(s, newAutoBanConfig(1))
	if err != nil {
		t.Fatal(err)
	}
	sk, _ := newKeyPair(t)
	_, victim := newKeyPair(t)
	forged := signedEvent(t, sk, nostr.KindReaction, "spam", nil)
	forged.PubKey = victim
	forged.ID = forged.GetID() // Valid body hash, but no signature from the victim.
	filter.HandleRejection(context.Background(), forged, "ModerationFilter")
	if err := filter.Close(); err != nil {
		t.Fatal(err)
	}
	if s.banCount() != 0 {
		t.Fatal("an invalid signature caused a ban on the impersonated author")
	}
}

func TestAutoBanIgnoresReplayedRejections(t *testing.T) {
	s := newTestStore()
	filter, err := NewAutoBanFilter(s, newAutoBanConfig(2))
	if err != nil {
		t.Fatal(err)
	}
	sk, _ := newKeyPair(t)
	event := signedEvent(t, sk, nostr.KindTextNote, "rejected elsewhere", nil)
	filter.HandleRejection(context.Background(), event, "SizeFilter")
	filter.HandleRejection(context.Background(), event, "SizeFilter")
	caseVariant := *event
	caseVariant.ID = strings.ToUpper(event.ID)
	filter.HandleRejection(context.Background(), &caseVariant, "SizeFilter")
	// CheckSignature verifies the body, not ID: changing ID must not defeat deduplication.
	forgedID := *event
	forgedID.ID = "0000000000000000000000000000000000000000000000000000000000000000"
	filter.HandleRejection(context.Background(), &forgedID, "SizeFilter")
	if err := filter.Close(); err != nil {
		t.Fatal(err)
	}
	if s.banCount() != 0 {
		t.Fatal("replaying one signed event banned its author")
	}
}

func TestAutoBanDiscardsStrikesOutsideWindow(t *testing.T) {
	s := newTestStore()
	cfg := newAutoBanConfig(2)
	filter, err := NewAutoBanFilter(s, cfg)
	if err != nil {
		t.Fatal(err)
	}
	sk, pubkey := newKeyPair(t)
	// Cache activity renews the entry TTL, but must not extend the strike window.
	filter.strikes.Add(pubkey, &RejectionStats{StrikeCount: 1, FirstStrikeTime: time.Now().Add(-2 * cfg.StrikeWindow)})
	filter.HandleRejection(context.Background(), signedEvent(t, sk, nostr.KindTextNote, "spam", nil), "SizeFilter")
	if err := filter.Close(); err != nil {
		t.Fatal(err)
	}
	if s.banCount() != 0 {
		t.Fatal("old strikes outside strike_window caused an automatic ban")
	}
}

func TestAutoBanBanSurvivesCanceledRequestContext(t *testing.T) {
	s := newTestStore()
	s.honorContext = true
	filter, err := NewAutoBanFilter(s, newAutoBanConfig(1))
	if err != nil {
		t.Fatal(err)
	}
	sk, pubkey := newKeyPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	filter.HandleRejection(ctx, signedEvent(t, sk, nostr.KindTextNote, "spam", nil), "SizeFilter")
	if err := filter.Close(); err != nil {
		t.Fatal(err)
	}
	if !s.isBanned(pubkey) {
		t.Fatal("auto-ban was dropped because the request context was canceled")
	}
}

func TestAutoBanRequiresConfiguredStrikes(t *testing.T) {
	s := newTestStore()
	filter, err := NewAutoBanFilter(s, newAutoBanConfig(2))
	if err != nil {
		t.Fatal(err)
	}
	sk, _ := newKeyPair(t)
	event := signedEvent(t, sk, nostr.KindTextNote, "spam", nil)
	// strfry compares decoded ID bytes, so uppercase hex is equally valid.
	event.ID = strings.ToUpper(event.ID)
	filter.HandleRejection(context.Background(), event, "SizeFilter")
	if s.banCount() != 0 {
		t.Fatal("author was banned before reaching max strikes")
	}
	second := signedEvent(t, sk, nostr.KindTextNote, "different spam", nil)
	second.ID = strings.ToUpper(second.ID)
	filter.HandleRejection(context.Background(), second, "SizeFilter")
	if err := filter.Close(); err != nil {
		t.Fatal(err)
	}
	if s.banCount() != 1 {
		t.Fatal("author was not banned after reaching max strikes")
	}
}

func TestAutoBanDisabledDoesNothing(t *testing.T) {
	s := newTestStore()
	cfg := newAutoBanConfig(1)
	cfg.Enabled = false
	filter, err := NewAutoBanFilter(s, cfg)
	if err != nil {
		t.Fatal(err)
	}
	sk, _ := newKeyPair(t)
	filter.HandleRejection(context.Background(), signedEvent(t, sk, nostr.KindTextNote, "spam", nil), "SizeFilter")
	if err := filter.Close(); err != nil {
		t.Fatal(err)
	}
	if s.banCount() != 0 {
		t.Fatal("disabled autoban banned an author")
	}
}

func TestAutoBanExcludesConfiguredFilters(t *testing.T) {
	s := newTestStore()
	cfg := newAutoBanConfig(1)
	cfg.ExcludeFilters = []string{"SizeFilter"}
	filter, err := NewAutoBanFilter(s, cfg)
	if err != nil {
		t.Fatal(err)
	}
	sk, _ := newKeyPair(t)
	event := signedEvent(t, sk, nostr.KindTextNote, "spam", nil)
	filter.HandleRejection(context.Background(), event, "SizeFilter")
	if s.banCount() != 0 {
		t.Fatal("rejection from an excluded filter counted as a strike")
	}
	filter.HandleRejection(context.Background(), event, "KindFilter")
	if err := filter.Close(); err != nil {
		t.Fatal(err)
	}
	if s.banCount() != 1 {
		t.Fatal("non-excluded filter did not trigger a ban")
	}
}

func TestAutoBanCloseWaitsForPendingBan(t *testing.T) {
	s := newTestStore()
	s.banStarted = make(chan struct{})
	block := make(chan struct{})
	s.banBlock = block
	filter, err := NewAutoBanFilter(s, newAutoBanConfig(1))
	if err != nil {
		t.Fatal(err)
	}
	sk, _ := newKeyPair(t)
	filter.HandleRejection(context.Background(), signedEvent(t, sk, nostr.KindTextNote, "spam", nil), "SizeFilter")
	select {
	case <-s.banStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("ban never started")
	}
	closed := make(chan error, 1)
	go func() { closed <- filter.Close() }()
	select {
	case err := <-closed:
		t.Fatalf("Close returned %v while a ban was still running", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(block)
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not return after the pending ban finished")
	}
}
