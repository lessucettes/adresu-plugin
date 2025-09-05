// policy/repost_abuse_filter_test.go
package policy

import (
	"context"
	"testing"
	"time"

	"adresu-plugin/config"
	"adresu-plugin/testutils"

	"github.com/nbd-wtf/go-nostr"
	"github.com/stretchr/testify/require"
)

// makeRepostKind6 returns a NIP-18 kind 6 repost.
func makeRepostKind6(pub string) *nostr.Event {
	return testutils.MakeEvent(nostr.KindRepost, "", pub, time.Now())
}

// makeGenericRepost returns a generic repost (kind 16).
func makeGenericRepost(pub string) *nostr.Event {
	return testutils.MakeEvent(16, "", pub, time.Now())
}

// makeQuote builds a kind-1 quote with an optional NIP-21 reference in content.
func makeQuote(pub string, withNIP21 bool) *nostr.Event {
	content := "quoted"
	if withNIP21 {
		// Minimal NIP-21-looking reference to satisfy strict mode when enabled.
		content += " nevent1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
	}
	ev := testutils.MakeEvent(nostr.KindTextNote, content, pub, time.Now(), nostr.Tag{"q", "dummy"})
	return ev
}

// Disabled filter must be a no-op and accept everything.
func TestRepostAbuseFilter_Disabled_IsNoop(t *testing.T) {
	cfg := &config.RepostAbuseFilterConfig{
		Enabled:               false,
		MaxRatio:              0.50,
		MinEvents:             4,
		ResetDuration:         10 * time.Second,
		CacheTTL:              time.Hour,
		CountRejectAsActivity: true,
		RequireNIP21InQuote:   true,
	}
	f := NewRepostAbuseFilter(cfg)

	ctx := context.Background()
	pub := "alice"

	events := []*nostr.Event{
		testutils.MakeTextNote(pub, "hello", time.Now()),
		makeRepostKind6(pub),
		makeGenericRepost(pub),
		makeQuote(pub, true),
	}

	for i, ev := range events {
		res := f.Check(ctx, ev, "127.0.0.1")
		require.Equal(t, ActionAccept, res.Action, "disabled filter must accept, idx=%d", i)
	}
}

// With MaxRatio=0.5 and MinEvents=4, after 4 originals the 4th repost should be rejected
// because the predictive ratio hits the threshold exactly: (reposts+1)/(total+1) >= 0.5.
func TestRepostAbuseFilter_RejectsTooManyReposts(t *testing.T) {
	cfg := &config.RepostAbuseFilterConfig{
		Enabled:               true,
		MaxRatio:              0.50,
		MinEvents:             4,
		ResetDuration:         0,
		CacheTTL:              time.Hour,
		CountRejectAsActivity: true,
		RequireNIP21InQuote:   true, // strict quotes (doesn't matter for this test)
	}
	f := NewRepostAbuseFilter(cfg)

	ctx := context.Background()
	pub := "bob"

	// 4 original posts → should all be accepted.
	for i := 0; i < 4; i++ {
		res := f.Check(ctx, testutils.MakeTextNote(pub, "hello", time.Now()), "ip1")
		require.Equal(t, ActionAccept, res.Action, "original #%d should be accepted", i+1)
	}

	// Now push reposts:
	// 1st repost: (0+1)/(4+1)=0.2 → accept
	require.Equal(t, ActionAccept, f.Check(ctx, makeRepostKind6(pub), "ip1").Action)
	// 2nd repost: (1+1)/(5+1)=0.333.. → accept
	require.Equal(t, ActionAccept, f.Check(ctx, makeGenericRepost(pub), "ip1").Action)
	// 3rd repost: (2+1)/(6+1)=0.428.. → accept
	require.Equal(t, ActionAccept, f.Check(ctx, makeRepostKind6(pub), "ip1").Action)
	// 4th repost: (3+1)/(7+1)=0.5 → reject (>= MaxRatio)
	require.Equal(t, ActionReject, f.Check(ctx, makeGenericRepost(pub), "ip1").Action)
}

// Soft reset: after ResetDuration of inactivity, counters should evaporate and enforcement relaxes again.
func TestRepostAbuseFilter_SoftReset(t *testing.T) {
	cfg := &config.RepostAbuseFilterConfig{
		Enabled:               true,
		MaxRatio:              0.50,
		MinEvents:             2,                     // require at least 2 prior events before enforcement
		ResetDuration:         60 * time.Millisecond, // short window for a fast test
		CacheTTL:              time.Hour,
		CountRejectAsActivity: true,
		RequireNIP21InQuote:   false,
	}
	f := NewRepostAbuseFilter(cfg)

	ctx := context.Background()
	pub := "carol"

	// Build up state below threshold, then let it reset, then verify acceptance again.
	require.Equal(t, ActionAccept, f.Check(ctx, testutils.MakeTextNote(pub, "hello", time.Now()), "ip1").Action) // O=1, R=0
	require.Equal(t, ActionAccept, f.Check(ctx, makeRepostKind6(pub), "ip1").Action)                             // total before enforcement < MinEvents (2) → accept

	// Sleep past the reset window to trigger a soft reset of counters.
	time.Sleep(80 * time.Millisecond)

	// After reset, another repost should be treated as if counters were fresh → accept.
	require.Equal(t, ActionAccept, f.Check(ctx, makeGenericRepost(pub), "ip1").Action)
}

// Quote handling sanity check: ensure quotes are treated as reposts only when configured so.
// Keep enforcement off on the very first quote by setting MinEvents=2.
func TestRepostAbuseFilter_Quote_StrictVsLooseDoesNotCrash(t *testing.T) {
	ctx := context.Background()
	pub := "dave"

	// Strict mode: require NIP-21 reference in content for quote classification.
	cfgStrict := &config.RepostAbuseFilterConfig{
		Enabled:               true,
		MaxRatio:              1.0, // would reject if enforced
		MinEvents:             2,   // DO NOT enforce on the first event
		ResetDuration:         0,
		CacheTTL:              time.Hour,
		CountRejectAsActivity: true,
		RequireNIP21InQuote:   true,
	}
	fStrict := NewRepostAbuseFilter(cfgStrict)

	// Loose mode: any 'q' tag counts as a repost (still no enforcement on the first event).
	cfgLoose := *cfgStrict
	cfgLoose.RequireNIP21InQuote = false
	fLoose := NewRepostAbuseFilter(&cfgLoose)

	// Quote without NIP-21
	evNoRef := makeQuote(pub, false)
	// Quote with NIP-21
	evWithRef := makeQuote(pub, true)

	require.Equal(t, ActionAccept, fStrict.Check(ctx, evNoRef, "ip1").Action)
	require.Equal(t, ActionAccept, fStrict.Check(ctx, evWithRef, "ip1").Action)
	require.Equal(t, ActionAccept, fLoose.Check(ctx, evNoRef, "ip1").Action)
	require.Equal(t, ActionAccept, fLoose.Check(ctx, evWithRef, "ip1").Action)
}
