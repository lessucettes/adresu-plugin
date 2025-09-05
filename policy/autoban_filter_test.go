// policy/autoban_filter_test.go
package policy

import (
	"context"
	"testing"
	"time"

	"adresu-plugin/config"
	"adresu-plugin/testutils"

	"github.com/stretchr/testify/require"
)

// Check should be a no-op (AutoBanFilter only reacts via HandleRejection).
func TestAutoBanFilter_Check_IsNoop(t *testing.T) {
	store := testutils.NewMockStoreWithSignal(1)
	cfg := &config.AutoBanFilterConfig{
		Enabled:      true,
		MaxStrikes:   3,
		StrikeWindow: time.Minute,
		BanDuration:  time.Hour,
	}

	f := NewAutoBanFilter(store, cfg)
	res := f.Check(context.Background(), testutils.MakeTextNote("alice", "hello", time.Now()), "1.2.3.4")
	require.Equal(t, ActionAccept, res.Action, "Check should be a no-op that always accepts")
}

// When disabled in config, HandleRejection must not trigger bans.
func TestAutoBanFilter_Disabled_NoBan(t *testing.T) {
	store := testutils.NewMockStoreWithSignal(1)
	cfg := &config.AutoBanFilterConfig{
		Enabled:      false, // filter is disabled
		MaxStrikes:   2,
		StrikeWindow: 100 * time.Millisecond,
		BanDuration:  30 * time.Minute,
	}

	f := NewAutoBanFilter(store, cfg)

	ctx := context.Background()
	ev := testutils.MakeTextNote("bob", "hello", time.Now())
	fn := "SomethingFilter"

	// Feed several rejections; none should result in a ban.
	f.HandleRejection(ctx, ev, fn)
	f.HandleRejection(ctx, ev, fn)
	f.HandleRejection(ctx, ev, fn)

	// If a ban were triggered, it would signal via channel; ensure it doesn't.
	select {
	case <-store.BanSignal:
		t.Fatalf("ban must not be triggered when the filter is disabled")
	case <-time.After(80 * time.Millisecond):
		// OK
	}

	require.Equal(t, 0, store.BanCalls, "no BanAuthor calls are expected when disabled")
}

// A ban should trigger exactly once after reaching MaxStrikes within StrikeWindow.
func TestAutoBanFilter_BansOnce_OnMaxStrikes(t *testing.T) {
	store := testutils.NewMockStoreWithSignal(2)
	cfg := &config.AutoBanFilterConfig{
		Enabled:      true,
		MaxStrikes:   3,
		StrikeWindow: time.Second,
		BanDuration:  45 * time.Minute,
	}

	f := NewAutoBanFilter(store, cfg)

	ctx := context.Background()
	pub := "carol"
	ev := testutils.MakeTextNote(pub, "hello", time.Now())
	fn := "SomethingFilter"

	// First two strikes: should not ban yet.
	f.HandleRejection(ctx, ev, fn)
	f.HandleRejection(ctx, ev, fn)

	// Ensure no early ban.
	select {
	case <-store.BanSignal:
		t.Fatalf("ban must not be triggered before reaching MaxStrikes")
	case <-time.After(50 * time.Millisecond):
		// OK
	}

	// Third strike within the window should trigger the ban (asynchronously).
	f.HandleRejection(ctx, ev, fn)

	// Expect exactly one ban signal for the correct pubkey.
	select {
	case gotPub := <-store.BanSignal:
		require.Equal(t, pub, gotPub, "ban should target the offending pubkey")
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("expected a ban after reaching MaxStrikes within StrikeWindow")
	}

	// Any immediate extra strike must NOT trigger a second ban (cooldown is active).
	f.HandleRejection(ctx, ev, fn)
	select {
	case <-store.BanSignal:
		t.Fatalf("a second ban must not fire immediately after the first (cooldown expected)")
	case <-time.After(80 * time.Millisecond):
		// OK
	}

	require.Equal(t, 1, store.BanCalls, "BanAuthor should be called exactly once")
}

// StrikeWindow expiration should reset counters, preventing a ban for spaced-out strikes.
func TestAutoBanFilter_StrikeWindow_ResetsCounters(t *testing.T) {
	store := testutils.NewMockStoreWithSignal(1)
	cfg := &config.AutoBanFilterConfig{
		Enabled:      true,
		MaxStrikes:   2,
		StrikeWindow: 80 * time.Millisecond, // short TTL to keep the test snappy
		BanDuration:  10 * time.Minute,
	}

	f := NewAutoBanFilter(store, cfg)

	ctx := context.Background()
	pub := "dave"
	ev := testutils.MakeTextNote(pub, "hello", time.Now())
	fn := "SomethingFilter"

	// First strike now…
	f.HandleRejection(ctx, ev, fn)

	// …wait until the strike window expires so the counter evaporates.
	time.Sleep(100 * time.Millisecond)

	// Next strike acts like the first of a new window — no ban should happen.
	f.HandleRejection(ctx, ev, fn)

	select {
	case <-store.BanSignal:
		t.Fatalf("ban must NOT trigger when strikes are separated by more than StrikeWindow")
	case <-time.After(60 * time.Millisecond):
		// OK
	}

	require.Equal(t, 0, store.BanCalls, "no BanAuthor call expected because the first strike expired")
}
