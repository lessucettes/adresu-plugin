package policy

import (
	"context"
	"testing"

	"fiatjaf.com/nostr"

	"github.com/lessucettes/adresu-plugin/pkg/adresu-kit/config"
)

func TestKeywordFilterMatchesStandaloneNonASCIIWords(t *testing.T) {
	cases := []struct {
		name    string
		word    string
		content string
	}{
		{"cyrillic at start", "спам", "спам и всё"},
		{"cyrillic in the middle", "спам", "это спам и всё"},
		{"cyrillic whole content", "спам", "спам"},
		{"cyrillic uppercase with punctuation", "спам", "СПАМ!"},
		{"japanese between spaces", "スパム", "これは スパム です"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			filter, err := NewKeywordFilter(&config.KeywordFilterConfig{
				Enabled: true,
				Rules: []config.KeywordRule{{
					Description: "test rule",
					Kinds:       []int{1},
					Words:       []string{tc.word},
				}},
			})
			if err != nil {
				t.Fatal(err)
			}

			res, err := filter.Match(context.Background(), &nostr.Event{Kind: 1, Content: tc.content}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if res.Allowed {
				t.Fatalf("content %q was allowed; word %q must match as a whole word", tc.content, tc.word)
			}
		})
	}
}

func TestKeywordFilterKeepsWholeWordSemantics(t *testing.T) {
	filter, err := NewKeywordFilter(&config.KeywordFilterConfig{
		Enabled: true,
		Rules: []config.KeywordRule{{
			Description: "test rule",
			Kinds:       []int{1},
			Words:       []string{"spam", "спам"},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, content := range []string{"this is spam", "это спам", "SPAM", "спам-ссылка"} {
		res, err := filter.Match(context.Background(), &nostr.Event{Kind: 1, Content: content}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if res.Allowed {
			t.Errorf("content %q was allowed, want a keyword match", content)
		}
	}

	for _, content := range []string{"spammer", "спамер", "notspam"} {
		res, err := filter.Match(context.Background(), &nostr.Event{Kind: 1, Content: content}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !res.Allowed {
			t.Errorf("content %q was rejected, want whole-word semantics to keep it allowed", content)
		}
	}
}

func TestKeywordFilterRegexpsAreUnchanged(t *testing.T) {
	filter, err := NewKeywordFilter(&config.KeywordFilterConfig{
		Enabled: true,
		Rules: []config.KeywordRule{{
			Description: "test rule",
			Kinds:       []int{1},
			Regexps:     []string{`https?://spam\.example`},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	res, err := filter.Match(context.Background(), &nostr.Event{Kind: 1, Content: "see https://spam.example now"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Allowed {
		t.Fatal("user regexp no longer matches")
	}
}
