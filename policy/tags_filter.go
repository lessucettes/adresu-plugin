// policy/tags_filter.go
package policy

import (
	"adresu-plugin/config"
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/nbd-wtf/go-nostr"
)

type TagsFilter struct{ kindToRule map[int]processedTagRule }

// processedTagRule holds a pre-compiled, ready-to-use version of a rule.
// All keys are stored in lowercase for efficient, case-insensitive matching.
type processedTagRule struct {
	source          *config.TagRule
	requiredTags    map[string]struct{}
	maxTagCounts    map[string]int
	originalCaseMap map[string]string
}

func NewTagsFilter(cfg *config.TagsFilterConfig) *TagsFilter {
	kindMap := make(map[int]processedTagRule)

	for i := range cfg.Rules {
		rule := &cfg.Rules[i]

		processed := processedTagRule{
			source:          rule,
			originalCaseMap: make(map[string]string),
		}

		if len(rule.RequiredTags) > 0 {
			processed.requiredTags = make(map[string]struct{}, len(rule.RequiredTags))
			for _, req := range rule.RequiredTags {
				lower := strings.ToLower(req)
				processed.requiredTags[lower] = struct{}{}
				processed.originalCaseMap[lower] = req
			}
		}
		if len(rule.MaxTagCounts) > 0 {
			processed.maxTagCounts = make(map[string]int, len(rule.MaxTagCounts))
			for key, val := range rule.MaxTagCounts {
				lower := strings.ToLower(key)
				processed.maxTagCounts[lower] = val
				processed.originalCaseMap[lower] = key
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
			fmt.Sprintf("blocked: too many tags for %s (got %d, max %d)", rule.Description, len(event.Tags), *rule.MaxTags),
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
			tagName := strings.ToLower(tag[0])

			if _, ok := processedRule.maxTagCounts[tagName]; ok {
				specificTagCounts[tagName]++
			}
			if _, ok := processedRule.requiredTags[tagName]; ok {
				requiredFound[tagName] = true
			}
		}

		for reqTagLower := range processedRule.requiredTags {
			if !requiredFound[reqTagLower] {
				originalTag := processedRule.originalCaseMap[reqTagLower]
				return Reject(
					fmt.Sprintf("blocked: missing required tag '%s' for %s", originalTag, rule.Description),
					slog.String("required_tag", originalTag),
					slog.String("rule_description", rule.Description),
				)
			}
		}

		for tagNameLower, limit := range processedRule.maxTagCounts {
			count := specificTagCounts[tagNameLower]
			if count > limit {
				originalTag := processedRule.originalCaseMap[tagNameLower]
				return Reject(
					fmt.Sprintf("blocked: too many '%s' tags for %s (got %d, max %d)", originalTag, rule.Description, count, limit),
					slog.String("tag_type", originalTag),
					slog.Int("tag_count", count),
					slog.Int("limit", limit),
					slog.String("rule_description", rule.Description),
				)
			}
		}
	}

	return Accept()
}
