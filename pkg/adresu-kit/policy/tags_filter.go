package policy

import (
	"context"
	"fmt"
	"maps"

	"github.com/nbd-wtf/go-nostr"

	"github.com/lessucettes/adresu-plugin/pkg/adresu-kit/config"
)

const (
	tagsFilterName = "TagsFilter"
)

type TagsFilter struct{ kindToRule map[int]processedTagRule }

type processedTagRule struct {
	source       *config.TagRule
	requiredTags map[string]struct{}
	maxTagCounts map[string]int
}

func NewTagsFilter(cfg *config.TagsFilterConfig) (*TagsFilter, error) {
	kindMap := make(map[int]processedTagRule)
	if cfg != nil {
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
				maps.Copy(processed.maxTagCounts, rule.MaxTagCounts)
			}
			for _, kind := range rule.Kinds {
				kindMap[kind] = processed
			}
		}
	}

	filter := &TagsFilter{kindToRule: kindMap}
	return filter, nil
}

func (f *TagsFilter) Match(_ context.Context, event *nostr.Event, meta map[string]any) (FilterResult, error) {
	newResult := NewResultFunc(tagsFilterName)

	processedRule, exists := f.kindToRule[event.Kind]
	if !exists {
		return newResult(true, "no_rules_for_kind", nil)
	}
	rule := processedRule.source

	if rule.MaxTags != nil && len(event.Tags) > *rule.MaxTags {
		reason := fmt.Sprintf("too_many_tags:got_%d,max_%d", len(event.Tags), *rule.MaxTags)
		return newResult(false, reason, nil)
	}

	if len(processedRule.requiredTags) > 0 || len(processedRule.maxTagCounts) > 0 {
		requiredFound := make(map[string]bool, len(processedRule.requiredTags))
		specificTagCounts := make(map[string]int, len(processedRule.maxTagCounts))

		for _, tag := range event.Tags {
			if len(tag) == 0 {
				continue
			}
			tagName := tag[0]

			if _, ok := processedRule.maxTagCounts[tagName]; ok {
				specificTagCounts[tagName]++
			}
			if _, ok := processedRule.requiredTags[tagName]; ok {
				requiredFound[tagName] = true
			}
		}

		for reqTag := range processedRule.requiredTags {
			if !requiredFound[reqTag] {
				reason := fmt.Sprintf("missing_required_tag:'%s'", reqTag)
				return newResult(false, reason, nil)
			}
		}

		for tagName, limit := range processedRule.maxTagCounts {
			count := specificTagCounts[tagName]
			if count > limit {
				reason := fmt.Sprintf("too_many_tags:'%s',got_%d,max_%d", tagName, count, limit)
				return newResult(false, reason, nil)
			}
		}
	}

	return newResult(true, "tags_ok", nil)
}
