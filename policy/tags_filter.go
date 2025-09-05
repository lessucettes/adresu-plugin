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

	if rule.MaxTags != nil && len(event.Tags) > *rule.MaxTags {
		slog.Warn("Rejecting event with too many tags",
			"ip", remoteIP, "pubkey", event.PubKey, "event_id", event.ID, "kind", event.Kind,
			"count", len(event.Tags), "limit", *rule.MaxTags, "rule", rule.Description)
		return Reject(fmt.Sprintf("blocked: too many tags for %s (got %d, max %d)", rule.Description, len(event.Tags), *rule.MaxTags))
	}

	for _, requiredTag := range rule.RequiredTags {
		if event.Tags.Find(requiredTag) == nil {
			slog.Warn("Rejecting event with missing required tag",
				"ip", remoteIP, "pubkey", event.PubKey, "event_id", event.ID, "kind", event.Kind,
				"required_tag", requiredTag, "rule", rule.Description)
			return Reject(fmt.Sprintf("blocked: missing required tag '%s' for %s", requiredTag, rule.Description))
		}
	}

	if len(rule.MaxTagCounts) > 0 {
		for tagIdentifier, limit := range rule.MaxTagCounts {
			count := 0
			for range event.Tags.FindAll(tagIdentifier) {
				count++
			}
			if count > limit {
				slog.Warn("Rejecting event with too many specific tags",
					"ip", remoteIP, "pubkey", event.PubKey, "event_id", event.ID, "kind", event.Kind,
					"tag_type", tagIdentifier, "count", count, "limit", limit, "rule", rule.Description)
				return Reject(fmt.Sprintf("blocked: too many '%s' tags for %s (got %d, max %d)", tagIdentifier, rule.Description, count, limit))
			}
		}
	}
	return Accept()
}
