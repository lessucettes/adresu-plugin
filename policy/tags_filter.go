// policy/tags_filter.go
package policy

import (
	"adresu-plugin/config"
	"context"
	"fmt"
	"log/slog"

	"github.com/nbd-wtf/go-nostr"
)

type TagsFilter struct{ kindToRule map[int]*config.TagRule }

func NewTagsFilter(cfg *config.TagsFilterConfig) *TagsFilter {
	kindMap := make(map[int]*config.TagRule, len(cfg.Rules))
	for i := range cfg.Rules {
		rule := &cfg.Rules[i]
		for _, kind := range rule.Kinds {
			kindMap[kind] = rule
		}
	}
	return &TagsFilter{kindToRule: kindMap}
}

func (f *TagsFilter) Name() string { return "TagsFilter" }

func (f *TagsFilter) Check(ctx context.Context, event *nostr.Event, remoteIP string) *Result {
	rule, exists := f.kindToRule[event.Kind]
	if !exists {
		return Accept()
	}

	// Condition 1: Max total number of tags
	if rule.MaxTags != nil && len(event.Tags) > *rule.MaxTags {
		return Reject(
			fmt.Sprintf("blocked: too many tags for %s (got %d, max %d)", rule.Description, len(event.Tags), *rule.MaxTags),
			slog.Int("tag_count", len(event.Tags)),
			slog.Int("limit", *rule.MaxTags),
			slog.String("rule_description", rule.Description),
		)
	}

	// Condition 2: Required tags
	for _, requiredTag := range rule.RequiredTags {
		if event.Tags.Find(requiredTag) == nil {
			return Reject(
				fmt.Sprintf("blocked: missing required tag '%s' for %s", requiredTag, rule.Description),
				slog.String("required_tag", requiredTag),
				slog.String("rule_description", rule.Description),
			)
		}
	}

	// Condition 3: Max count for specific tags
	if len(rule.MaxTagCounts) > 0 {
		for tagIdentifier, limit := range rule.MaxTagCounts {
			count := 0
			for range event.Tags.FindAll(tagIdentifier) {
				count++
			}
			if count > limit {
				return Reject(
					fmt.Sprintf("blocked: too many '%s' tags for %s (got %d, max %d)", tagIdentifier, rule.Description, count, limit),
					slog.String("tag_type", tagIdentifier),
					slog.Int("tag_count", count),
					slog.Int("limit", limit),
					slog.String("rule_description", rule.Description),
				)
			}
		}
	}
	return Accept()
}
