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

// makeEventAtTime is a small helper to create an event with a specific timestamp.
func makeEventAtTime(t time.Time) *nostr.Event {
	return &nostr.Event{
		PubKey:    "test_pubkey",
		CreatedAt: nostr.Timestamp(t.Unix()),
		Kind:      1,
		Content:   "test",
	}
}

func TestFreshnessFilter(t *testing.T) {
	ctx := context.Background()
	now := time.Now() // Use a fixed time for predictable test results.

	baseCfg := &config.FreshnessFilterConfig{
		MaxPast:   time.Hour,       // Allow events up to 1 hour old.
		MaxFuture: 5 * time.Minute, // Allow events up to 5 minutes in the future.
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
			name:           "Should accept old event if MaxPast is zero (disabled)",
			cfg:            &config.FreshnessFilterConfig{MaxPast: 0, MaxFuture: 5 * time.Minute},
			eventTime:      now.Add(-48 * time.Hour),
			expectedAction: ActionAccept,
		},
		{
			name:           "Should accept future event if MaxFuture is zero (disabled)",
			cfg:            &config.FreshnessFilterConfig{MaxPast: time.Hour, MaxFuture: 0},
			eventTime:      now.Add(48 * time.Hour),
			expectedAction: ActionAccept,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			filter := NewFreshnessFilter(tc.cfg)
			event := makeEventAtTime(tc.eventTime)

			result := filter.Check(ctx, event, "127.0.0.1")

			require.Equal(t, tc.expectedAction, result.Action)
		})
	}
}

func TestFreshnessFilter_UpdateConfig(t *testing.T) {
	ctx := context.Background()

	// 1. Start with a permissive config (allows events up to 1 hour old).
	initialCfg := &config.FreshnessFilterConfig{MaxPast: time.Hour, MaxFuture: time.Minute}
	filter := NewFreshnessFilter(initialCfg)

	// 2. Create an event that is 30 minutes old, which should be accepted.
	event := makeEventAtTime(time.Now().Add(-30 * time.Minute))
	require.Equal(t, ActionAccept, filter.Check(ctx, event, "").Action, "Event should be accepted with initial config")

	// 3. Create a new, stricter global config (only allows events up to 10 minutes old).
	stricterGlobalCfg := &config.Config{
		Filters: config.FiltersConfig{
			Freshness: config.FreshnessFilterConfig{
				MaxPast: 10 * time.Minute, MaxFuture: time.Minute,
			},
		},
	}

	// 4. Apply the new, stricter config.
	err := filter.UpdateConfig(stricterGlobalCfg)
	require.NoError(t, err)

	// 5. Check the same 30-minute-old event again. Now it should be rejected.
	require.Equal(t, ActionReject, filter.Check(ctx, event, "").Action, "Event should be rejected after config update")
}
