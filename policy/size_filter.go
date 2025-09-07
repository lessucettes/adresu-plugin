// policy/size_filter.go
package policy

import (
	"adresu-plugin/config"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"

	"github.com/nbd-wtf/go-nostr"
)

type SizeFilter struct {
	mu         sync.RWMutex
	cfg        *config.SizeFilterConfig
	kindToRule map[int]*config.SizeRule
}

func NewSizeFilter(cfg *config.SizeFilterConfig) *SizeFilter {
	kindMap := make(map[int]*config.SizeRule, len(cfg.Rules))
	for i := range cfg.Rules {
		rule := &cfg.Rules[i]
		for _, kind := range rule.Kinds {
			kindMap[kind] = rule
		}
	}
	return &SizeFilter{cfg: cfg, kindToRule: kindMap}
}

func (f *SizeFilter) Name() string { return "SizeFilter" }

func (f *SizeFilter) Check(ctx context.Context, event *nostr.Event, remoteIP string) *Result {
	f.mu.RLock()
	maxSize := f.cfg.DefaultMaxSize
	description := "default event"
	if rule, ok := f.kindToRule[event.Kind]; ok {
		maxSize = rule.MaxSize
		description = rule.Description
	}
	f.mu.RUnlock()

	if maxSize == 0 {
		return Accept()
	}

	raw, err := json.Marshal(event)
	if err != nil {
		slog.Error("Failed to marshal event for size check", "error", err, "event_id", event.ID, "ip", remoteIP)
		return Reject("internal: failed to process event")
	}
	size := len(raw)

	if size > maxSize {
		slog.Warn("Rejecting oversized event",
			"ip", remoteIP, "pubkey", event.PubKey, "event_id", event.ID, "kind", event.Kind,
			"size", size, "limit", maxSize, "rule", description)
		return Reject(fmt.Sprintf("blocked: event size %d bytes exceeds limit of %d for %s", size, maxSize, description))
	}
	return Accept()
}

func (f *SizeFilter) UpdateConfig(cfg *config.Config) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	newCfg := &cfg.Filters.Size
	newKindMap := make(map[int]*config.SizeRule, len(newCfg.Rules))
	for i := range newCfg.Rules {
		rule := &newCfg.Rules[i]
		for _, kind := range rule.Kinds {
			newKindMap[kind] = rule
		}
	}

	f.cfg = newCfg
	f.kindToRule = newKindMap

	slog.Info("SizeFilter configuration updated",
		"default_max_size", f.cfg.DefaultMaxSize,
		"rules_count", len(f.cfg.Rules))
	return nil
}
