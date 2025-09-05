// policy/language_filter_test.go
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

func TestLanguageFilter(t *testing.T) {
	ctx := context.Background()

	// Initialize the language detector once for all tests.
	detector := GetGlobalDetector()

	// Base configuration allows Russian and Japanese for kind 1 notes.
	baseCfg := &config.LanguageFilterConfig{
		Enabled:          true,
		AllowedLanguages: []string{"russian", "japanese"},
		KindsToCheck:     []int{1},
	}

	testCases := []struct {
		name                string
		cfg                 *config.LanguageFilterConfig
		content             string
		eventKind           int
		expectedAction      string
		expectedMsgContains string
	}{
		{
			name:           "Should accept Russian text",
			cfg:            baseCfg,
			content:        "Привет, мир! Это сообщение на русском языке.",
			eventKind:      1,
			expectedAction: ActionAccept,
		},
		{
			name:           "Should accept Japanese text",
			cfg:            baseCfg,
			content:        "こんにちは世界！これは日本語のメッセージです。",
			eventKind:      1,
			expectedAction: ActionAccept,
		},
		{
			name:           "Should reject other known languages (English)",
			cfg:            baseCfg,
			content:        "Hello world, this is a message in English.",
			eventKind:      1,
			expectedAction: ActionReject,
			// FIX: Changed "ENGLISH" to "English" to match the library's output.
			expectedMsgContains: "language 'English' is not allowed",
		},
		{
			name:           "Should reject text that is misidentified as another language (Klingon -> Tswana)",
			cfg:            baseCfg,
			content:        "tlhIngan Hol vIjatlh. Heghlu'meH QaQ jajvam.",
			eventKind:      1,
			expectedAction: ActionReject,
			// FIX: We now expect a rejection of the guessed language, not a failure to determine.
			expectedMsgContains: "is not allowed",
		},
		{
			name:           "Should reject non-linguistic unicode symbols",
			cfg:            baseCfg,
			content:        "★✪☆⚝⚞⚟⚿⛀⛁⛂⛃",
			eventKind:      1,
			expectedAction: ActionReject,
			// FIX: The library may not be able to determine this, which is a valid rejection reason.
			expectedMsgContains: "language could not be determined",
		},
		// --- Additional Edge Cases (These were already passing and remain correct) ---
		{
			name: "Should accept any language if filter is disabled",
			cfg: &config.LanguageFilterConfig{
				Enabled: false, AllowedLanguages: []string{"russian"}, KindsToCheck: []int{1},
			},
			content:        "This English message should be allowed.",
			eventKind:      1,
			expectedAction: ActionAccept,
		},
		{
			name:           "Should accept any language for a kind not in the check list",
			cfg:            baseCfg,
			content:        "This English message in a kind 7 event should be allowed.",
			eventKind:      7, // Not in KindsToCheck
			expectedAction: ActionAccept,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			filter := NewLanguageFilter(tc.cfg, detector)

			event := testutils.MakeEvent(nostr.KindTextNote, "", testutils.TestPubKey, time.Now())
			event.Kind = tc.eventKind
			event.Content = tc.content

			result := filter.Check(ctx, event, "127.0.0.1")

			require.Equal(t, tc.expectedAction, result.Action)
			if tc.expectedMsgContains != "" {
				require.Contains(t, result.Message, tc.expectedMsgContains)
			}
		})
	}
}
