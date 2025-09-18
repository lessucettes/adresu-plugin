// policy/freshness_filter_test.go
package policy

import (
	"context"
	"testing"
	"time"

	"adresu-plugin/config"

	"github.com/nbd-wtf/go-nostr"
	"github.com/stretchr/testify/require"
)

func makeEventAtTime(t time.Time, kind int) *nostr.Event {
	return &nostr.Event{
		PubKey:    "test_pubkey",
		CreatedAt: nostr.Timestamp(t.Unix()),
		Kind:      kind,
		Content:   "test",
	}
}

func TestFreshnessFilter_Defaults(t *testing.T) {
	ctx := context.Background()
	now := time.Now() // Use a fixed time for predictable test results.

	baseCfg := &config.FreshnessFilterConfig{
		DefaultMaxPast:   time.Hour,       // Allow events up to 1 hour old.
		DefaultMaxFuture: 5 * time.Minute, // Allow events up to 5 minutes in the future.
	}

	testCases := []struct {
		name           string
		cfg            *config.FreshnessFilterConfig
		eventTime      time.Time
		expectedAction string
	}{
		{
			name:           "Should accept event with current timestamp",
			cfg:            baseCfg,
			eventTime:      now,
			expectedAction: ActionAccept,
		},
		{
			name:           "Should accept recent past event within limit",
			cfg:            baseCfg,
			eventTime:      now.Add(-30 * time.Minute),
			expectedAction: ActionAccept,
		},
		{
			name:           "Should reject stale event outside limit",
			cfg:            baseCfg,
			eventTime:      now.Add(-2 * time.Hour),
			expectedAction: ActionReject,
		},
		{
			name:           "Should accept near future event within limit",
			cfg:            baseCfg,
			eventTime:      now.Add(2 * time.Minute),
			expectedAction: ActionAccept,
		},
		{
			name:           "Should reject far future event outside limit",
			cfg:            baseCfg,
			eventTime:      now.Add(10 * time.Minute),
			expectedAction: ActionReject,
		},
		{
			name:           "Should accept old event if DefaultMaxPast is zero (disabled)",
			cfg:            &config.FreshnessFilterConfig{DefaultMaxPast: 0, DefaultMaxFuture: 5 * time.Minute},
			eventTime:      now.Add(-48 * time.Hour),
			expectedAction: ActionAccept,
		},
		{
			name:           "Should accept future event if DefaultMaxFuture is zero (disabled)",
			cfg:            &config.FreshnessFilterConfig{DefaultMaxPast: time.Hour, DefaultMaxFuture: 0},
			eventTime:      now.Add(48 * time.Hour),
			expectedAction: ActionAccept,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			filter := NewFreshnessFilter(tc.cfg)
			event := makeEventAtTime(tc.eventTime, 1)

			result := filter.Check(ctx, event, "127.0.0.1")

			require.Equal(t, tc.expectedAction, result.Action)
		})
	}
}

func TestFreshnessFilter_WithRules(t *testing.T) {
	ctx := context.Background()
	now := time.Now()

	cfg := &config.FreshnessFilterConfig{
		DefaultMaxPast:   time.Second,
		DefaultMaxFuture: time.Second,
		Rules: []config.FreshnessRule{
			{
				Kinds:     []int{10002},
				MaxPast:   24 * time.Hour,
				MaxFuture: 10 * time.Minute,
			},
		},
	}

	filter := NewFreshnessFilter(cfg)

	eventForRule := makeEventAtTime(now.Add(-12*time.Hour), 10002)
	require.Equal(t, ActionAccept, filter.Check(ctx, eventForRule, "").Action, "Should accept old event matching a specific rule")

	eventForDefault := makeEventAtTime(now.Add(-12*time.Hour), 1)
	require.Equal(t, ActionReject, filter.Check(ctx, eventForDefault, "").Action, "Should reject old event using default policy")
}

func TestFreshnessFilter_UpdateConfig(t *testing.T) {
	ctx := context.Background()

	// 1. Start with a permissive config.
	initialCfg := &config.FreshnessFilterConfig{DefaultMaxPast: time.Hour, DefaultMaxFuture: time.Minute}
	filter := NewFreshnessFilter(initialCfg)

	// 2. Create an event that is 30 minutes old, which should be accepted.
	event := makeEventAtTime(time.Now().Add(-30*time.Minute), 1)
	require.Equal(t, ActionAccept, filter.Check(ctx, event, "").Action, "Event should be accepted with initial config")

	// 3. Create a new, stricter global config.
	stricterGlobalCfg := &config.Config{
		Filters: config.FiltersConfig{
			Freshness: config.FreshnessFilterConfig{
				DefaultMaxPast: 10 * time.Minute, DefaultMaxFuture: time.Minute,
			},
		},
	}

	// 4. Apply the new, stricter config.
	err := filter.UpdateConfig(stricterGlobalCfg)
	require.NoError(t, err)

	// 5. Check the same 30-minute-old event again. Now it should be rejected.
	require.Equal(t, ActionReject, filter.Check(ctx, event, "").Action, "Event should be rejected after config update")
}
