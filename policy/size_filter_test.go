// policy/size_filter_test.go
package policy

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"adresu-plugin/config"
	"adresu-plugin/testutils"

	"github.com/nbd-wtf/go-nostr"
	"github.com/stretchr/testify/require"
)

func TestSizeFilter(t *testing.T) {
	ctx := context.Background()
	testPubKey := "test_pubkey_for_size_filter"

	t.Run("accepts event below limit", func(t *testing.T) {
		filter := NewSizeFilter(&config.SizeFilterConfig{DefaultMaxSize: 500})
		event := testutils.MakeEvent(nostr.KindTextNote, "", testPubKey, time.Now())
		event.Content = "small content"

		result := filter.Check(ctx, event, "127.0.0.1")
		require.Equal(t, ActionAccept, result.Action)
	})

	t.Run("accepts event exactly at limit", func(t *testing.T) {
		event := testutils.MakeEvent(nostr.KindTextNote, "", testPubKey, time.Now())
		event.Content = strings.Repeat("a", 10)

		// Marshal the event first to get its exact, final size.
		raw, err := json.Marshal(event)
		require.NoError(t, err)
		exactSize := len(raw)

		// Set the filter's limit to be exactly that size.
		filter := NewSizeFilter(&config.SizeFilterConfig{DefaultMaxSize: exactSize})
		result := filter.Check(ctx, event, "127.0.0.1")
		require.Equal(t, ActionAccept, result.Action, "event with size equal to limit should be accepted")
	})

	t.Run("rejects event just over limit", func(t *testing.T) {
		event := testutils.MakeEvent(nostr.KindTextNote, "", testPubKey, time.Now())
		event.Content = strings.Repeat("a", 10)

		raw, err := json.Marshal(event)
		require.NoError(t, err)
		limit := len(raw) - 1 // one less than actual size

		filter := NewSizeFilter(&config.SizeFilterConfig{DefaultMaxSize: limit})
		result := filter.Check(ctx, event, "127.0.0.1")
		require.Equal(t, ActionReject, result.Action)
	})

	t.Run("applies stricter kind-specific rule", func(t *testing.T) {
		cfg := &config.SizeFilterConfig{
			DefaultMaxSize: 1000, // permissive default
			Rules: []config.SizeRule{
				{Kinds: []int{7}, MaxSize: 100}, // strict rule
			},
		}
		filter := NewSizeFilter(cfg)

		// Build event as kind 7 up front.
		event := testutils.MakeEvent(7, strings.Repeat("a", 200), testPubKey, time.Now()) // >100 bytes, <1000 bytes

		result := filter.Check(ctx, event, "127.0.0.1")
		require.Equal(t, ActionReject, result.Action)
	})
}

func TestSizeFilter_UpdateConfig(t *testing.T) {
	ctx := context.Background()
	initialCfg := &config.SizeFilterConfig{DefaultMaxSize: 1024}
	filter := NewSizeFilter(initialCfg)

	event := testutils.MakeEvent(nostr.KindTextNote, strings.Repeat("a", 500), "pubkey_for_update", time.Now())
	require.Equal(t, ActionAccept, filter.Check(ctx, event, "").Action)

	stricterGlobalCfg := &config.Config{
		Filters: config.FiltersConfig{
			Size: config.SizeFilterConfig{DefaultMaxSize: 256},
		},
	}
	err := filter.UpdateConfig(stricterGlobalCfg)
	require.NoError(t, err)
	require.Equal(t, ActionReject, filter.Check(ctx, event, "").Action)
}
