// policy/keyword_filter_test.go
package policy

import (
	"context"
	"testing"

	"adresu-plugin/config"

	"github.com/nbd-wtf/go-nostr"
	"github.com/stretchr/testify/require"
)

func TestNewKeywordFilter(t *testing.T) {
	t.Run("should create filter with valid config", func(t *testing.T) {
		cfg := &config.KeywordFilterConfig{
			Rules: []config.KeywordRule{{
				Regexps: []string{`^\d+$`}, // Valid regex
			}},
		}
		_, err := NewKeywordFilter(cfg)
		require.NoError(t, err)
	})

	t.Run("should fail to create filter with invalid regexp", func(t *testing.T) {
		cfg := &config.KeywordFilterConfig{
			Rules: []config.KeywordRule{{
				Regexps: []string{`[`}, // Invalid regex
			}},
		}
		_, err := NewKeywordFilter(cfg)
		require.Error(t, err, "Expected an error due to invalid regex")
	})
}

func TestKeywordFilter_Check(t *testing.T) {
	baseCfg := &config.KeywordFilterConfig{
		Enabled: true,
		Rules: []config.KeywordRule{
			{
				Description: "Block spammy content in notes",
				Kinds:       []int{1},
				Words:       []string{"viagra", "sale"},
				Regexps:     []string{`\bcash\s*app\b`}, // case-insensitive due to (?i) flag in implementation
			},
			{
				Description: "Block only numbers in profile updates",
				Kinds:       []int{0},
				Regexps:     []string{`^\d+$`},
			},
		},
	}

	testCases := []struct {
		name           string
		cfg            *config.KeywordFilterConfig
		event          *nostr.Event
		expectedAction string
	}{
		{
			name:           "Filter disabled, should accept",
			cfg:            &config.KeywordFilterConfig{Enabled: false, Rules: baseCfg.Rules},
			event:          makeTestEventWithContent("pk1", 1, "buy viagra now!"),
			expectedAction: ActionAccept,
		},
		{
			name:           "No rule for kind, should accept",
			cfg:            baseCfg,
			event:          makeTestEventWithContent("pk1", 7, "big sale today"), // kind 7 has no rules
			expectedAction: ActionAccept,
		},
		{
			name:           "Simple word match, should reject",
			cfg:            baseCfg,
			event:          makeTestEventWithContent("pk1", 1, "big viagra sale"),
			expectedAction: ActionReject,
		},
		{
			name:           "Case-insensitive word match, should reject",
			cfg:            baseCfg,
			event:          makeTestEventWithContent("pk1", 1, "BIG SALE TODAY"),
			expectedAction: ActionReject,
		},
		{
			name:           "Custom regex match, should reject",
			cfg:            baseCfg,
			event:          makeTestEventWithContent("pk1", 1, "send money to my cash app"),
			expectedAction: ActionReject,
		},
		{
			name:           "Partial word match, should accept",
			cfg:            baseCfg,
			event:          makeTestEventWithContent("pk1", 1, "this is a wholesale deal"), // "sale" is a substring of "wholesale"
			expectedAction: ActionAccept,
		},
		{
			name:           "Clean content, should accept",
			cfg:            baseCfg,
			event:          makeTestEventWithContent("pk1", 1, "hello world, this is a clean message"),
			expectedAction: ActionAccept,
		},
		{
			name:           "Rule for different kind, should reject",
			cfg:            baseCfg,
			event:          makeTestEventWithContent("pk1", 0, "12345"), // kind 0, content is only numbers
			expectedAction: ActionReject,
		},
		{
			name:           "Rule for different kind, should accept",
			cfg:            baseCfg,
			event:          makeTestEventWithContent("pk1", 0, "My new name is 123"), // kind 0, content is not only numbers
			expectedAction: ActionAccept,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			filter, err := NewKeywordFilter(tc.cfg)
			require.NoError(t, err)

			result := filter.Check(context.Background(), tc.event, "127.0.0.1")
			require.Equal(t, tc.expectedAction, result.Action)
		})
	}
}

func TestKeywordFilter_UpdateConfig(t *testing.T) {
	ctx := context.Background()

	// 1. Start with a permissive config.
	initialCfg := &config.KeywordFilterConfig{Enabled: true}
	filter, err := NewKeywordFilter(initialCfg)
	require.NoError(t, err)

	// 2. Check an event that should be allowed initially.
	event := makeTestEventWithContent("pk1", 1, "buy my new widget")
	require.Equal(t, ActionAccept, filter.Check(ctx, event, "").Action)

	// 3. Create a new, stricter global config.
	stricterCfg := &config.Config{
		Filters: config.FiltersConfig{
			Keywords: config.KeywordFilterConfig{
				Enabled: true,
				Rules: []config.KeywordRule{
					{Kinds: []int{1}, Words: []string{"widget"}},
				},
			},
		},
	}

	// 4. Apply the new config.
	err = filter.UpdateConfig(stricterCfg)
	require.NoError(t, err)

	// 5. Check the same event again. Now it should be rejected.
	require.Equal(t, ActionReject, filter.Check(ctx, event, "").Action, "Filter should reject event after config update")

	// 6. Test updating with an invalid config.
	invalidCfg := &config.Config{
		Filters: config.FiltersConfig{
			Keywords: config.KeywordFilterConfig{
				Enabled: true,
				Rules:   []config.KeywordRule{{Regexps: []string{"["}}}, // Invalid regex
			},
		},
	}
	err = filter.UpdateConfig(invalidCfg)
	require.Error(t, err, "UpdateConfig should fail with an invalid new configuration")
}

// makeTestEventWithContent is a small helper for this file.
func makeTestEventWithContent(pubkey string, kind int, content string) *nostr.Event {
	return &nostr.Event{
		PubKey:    pubkey,
		Kind:      kind,
		Content:   content,
		CreatedAt: nostr.Now(),
	}
}
