package policy

import (
	"context"
	"fmt"
	"regexp"

	"github.com/nbd-wtf/go-nostr"

	"github.com/lessucettes/adresu-plugin/pkg/adresu-kit/config"
)

const (
	keywordFilterName = "KeywordFilter"
)

type compiledKeywordRule struct {
	source      string
	description string
	regex       *regexp.Regexp
}

type KeywordFilter struct {
	enabled     bool
	kindToRules map[int][]compiledKeywordRule
}

func NewKeywordFilter(cfg *config.KeywordFilterConfig) (*KeywordFilter, error) {
	if !cfg.Enabled {
		return &KeywordFilter{enabled: false}, nil
	}

	kindMap := make(map[int][]compiledKeywordRule)

	for _, rule := range cfg.Rules {
		// Compile simple words into case-insensitive whole-word regexes.
		for _, word := range rule.Words {
			compiled, err := regexp.Compile(`(?i)\b` + regexp.QuoteMeta(word) + `\b`)
			if err != nil {
				return nil, fmt.Errorf("internal error compiling keyword '%s': %w", word, err)
			}
			ckr := compiledKeywordRule{
				source:      word,
				description: rule.Description,
				regex:       compiled,
			}
			for _, kind := range rule.Kinds {
				kindMap[kind] = append(kindMap[kind], ckr)
			}
		}

		// Compile user-provided regexes as they are.
		for _, rx := range rule.Regexps {
			compiled, err := regexp.Compile(rx)
			if err != nil {
				return nil, fmt.Errorf("failed to compile user regexp '%s' for rule '%s': %w", rx, rule.Description, err)
			}
			ckr := compiledKeywordRule{
				source:      rx,
				description: rule.Description,
				regex:       compiled,
			}
			for _, kind := range rule.Kinds {
				kindMap[kind] = append(kindMap[kind], ckr)
			}
		}
	}

	filter := &KeywordFilter{
		enabled:     cfg.Enabled,
		kindToRules: kindMap,
	}

	return filter, nil
}

func (f *KeywordFilter) Match(_ context.Context, event *nostr.Event, meta map[string]any) (FilterResult, error) {
	newResult := NewResultFunc(keywordFilterName)

	if !f.enabled {
		return newResult(true, "filter_disabled", nil)
	}

	rules, exists := f.kindToRules[event.Kind]
	if !exists {
		return newResult(true, "no_rules_for_kind", nil)
	}

	for _, rule := range rules {
		if rule.regex.MatchString(event.Content) {
			reason := fmt.Sprintf("forbidden_pattern_found:'%s'", rule.source)
			return newResult(false, reason, nil)
		}
	}

	return newResult(true, "no_forbidden_patterns_found", nil)
}
