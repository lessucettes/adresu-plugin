// policy/tags_filter.go
package policy

import (
	"adresu-plugin/config"
	"context"
	"fmt"
	"log/slog"

	"github.com/nbd-wtf/go-nostr"
)

type TagsFilter struct{ kindToRule map[int]processedTagRule }

// processedTagRule holds a pre-compiled, ready-to-use version of a rule.
type processedTagRule struct {
	source       *config.TagRule
	requiredTags map[string]struct{}
	maxTagCounts map[string]int
}

func NewTagsFilter(cfg *config.TagsFilterConfig) *TagsFilter {
	kindMap := make(map[int]processedTagRule)

	for i := range cfg.Rules {
		rule := &cfg.Rules[i]

		processed := processedTagRule{
			source:       rule,
			requiredTags: make(map[string]struct{}),
			maxTagCounts: make(map[string]int),
		}

		if len(rule.RequiredTags) > 0 {
			for _, req := range rule.RequiredTags {
				processed.requiredTags[req] = struct{}{}
			}
		}
		if len(rule.MaxTagCounts) > 0 {
			for key, val := range rule.MaxTagCounts {
				processed.maxTagCounts[key] = val
			}
		}

		for _, kind := range rule.Kinds {
			kindMap[kind] = processed
		}
	}
	return &TagsFilter{kindToRule: kindMap}
}

func (f *TagsFilter) Name() string { return "TagsFilter" }

func (f *TagsFilter) Check(ctx context.Context, event *nostr.Event, remoteIP string) *Result {
	processedRule, exists := f.kindToRule[event.Kind]
	if !exists {
		return Accept()
	}
	rule := processedRule.source

	if rule.MaxTags != nil && len(event.Tags) > *rule.MaxTags {
		return Reject(
			fmt.Sprintf("blocked: too many tags for %s (got %d, max %d)",
				rule.Description, len(event.Tags), *rule.MaxTags),
			slog.Int("tag_count", len(event.Tags)),
			slog.Int("limit", *rule.MaxTags),
			slog.String("rule_description", rule.Description),
		)
	}

	if len(processedRule.requiredTags) > 0 || len(processedRule.maxTagCounts) > 0 {
		requiredFound := make(map[string]bool, len(processedRule.requiredTags))
		specificTagCounts := make(map[string]int, len(processedRule.maxTagCounts))

		for _, tag := range event.Tags {
			if len(tag) == 0 || tag[0] == "" {
				continue
			}
			tagName := tag[0] // Case-sensitive: "L" ≠ "l".

			if _, ok := processedRule.maxTagCounts[tagName]; ok {
				specificTagCounts[tagName]++
			}
			if _, ok := processedRule.requiredTags[tagName]; ok {
				requiredFound[tagName] = true
			}
		}

		for reqTag := range processedRule.requiredTags {
			if !requiredFound[reqTag] {
				return Reject(
					fmt.Sprintf("blocked: missing required tag '%s' for %s", reqTag, rule.Description),
					slog.String("required_tag", reqTag),
					slog.String("rule_description", rule.Description),
				)
			}
		}

		for tagName, limit := range processedRule.maxTagCounts {
			count := specificTagCounts[tagName]
			if count > limit {
				return Reject(
					fmt.Sprintf("blocked: too many '%s' tags for %s (got %d, max %d)",
						tagName, rule.Description, count, limit),
					slog.String("tag_type", tagName),
					slog.Int("tag_count", count),
					slog.Int("limit", limit),
					slog.String("rule_description", rule.Description),
				)
			}
		}
	}

	return Accept()
}
