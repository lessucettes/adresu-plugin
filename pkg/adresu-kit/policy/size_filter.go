package policy

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/nbd-wtf/go-nostr"

	"github.com/lessucettes/adresu-plugin/pkg/adresu-kit/config"
)

const (
	sizeFilterName = "SizeFilter"
)

type SizeFilter struct {
	cfg        *config.SizeFilterConfig
	kindToRule map[int]*config.SizeRule
}

func NewSizeFilter(cfg *config.SizeFilterConfig) (*SizeFilter, error) {
	kindMap := make(map[int]*config.SizeRule)

	if cfg != nil {
		for i := range cfg.Rules {
			rule := &cfg.Rules[i]
			for _, kind := range rule.Kinds {
				kindMap[kind] = rule
			}
		}
	}

	filter := &SizeFilter{cfg: cfg, kindToRule: kindMap}
	return filter, nil
}

func (f *SizeFilter) Match(_ context.Context, event *nostr.Event, meta map[string]any) (FilterResult, error) {
	newResult := NewResultFunc(sizeFilterName)

	maxSize := 0
	if f.cfg != nil {
		maxSize = f.cfg.DefaultMaxSize
	}

	if rule, ok := f.kindToRule[event.Kind]; ok {
		maxSize = rule.MaxSize
	}

	if maxSize <= 0 {
		return newResult(true, "Event size is unlimited for this event kind.", nil)
	}

	raw, err := json.Marshal(event)
	if err != nil {
		// This is a critical error, propagate it to the pipeline.
		return newResult(false, "Failed to encode event as JSON for the size check.", err)
	}
	size := len(raw)

	if size > maxSize {
		reason := fmt.Sprintf("Event is too large (%d bytes; maximum allowed: %d bytes).", size, maxSize)
		return newResult(false, reason, nil)
	}

	return newResult(true, "Event size is within the allowed limit.", nil)
}
