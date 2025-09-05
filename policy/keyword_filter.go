// policy/keyword_filter.go
package policy

import (
	"adresu-plugin/config"
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"sync"

	"github.com/nbd-wtf/go-nostr"
)

// compiledKeywordRule holds a pre-compiled regex for efficient matching.
type compiledKeywordRule struct {
	source      string // The original word or regexp from the config for logging.
	description string // The description of the rule group.
	regex       *regexp.Regexp
}

// activeKeywordConfig holds a snapshot of the configuration and its derived data.
type activeKeywordConfig struct {
	raw         *config.KeywordFilterConfig
	kindToRules map[int][]compiledKeywordRule
}

type KeywordFilter struct {
	mu        sync.RWMutex
	activeCfg *activeKeywordConfig
}

func NewKeywordFilter(cfg *config.KeywordFilterConfig) (*KeywordFilter, error) {
	f := &KeywordFilter{}
	activeCfg, err := f.buildActiveConfig(cfg)
	if err != nil {
		return nil, err
	}
	f.activeCfg = activeCfg
	return f, nil
}

func (f *KeywordFilter) Name() string { return "KeywordFilter" }

func (f *KeywordFilter) Check(ctx context.Context, event *nostr.Event, remoteIP string) *Result {
	f.mu.RLock()
	cfg := f.activeCfg
	f.mu.RUnlock()

	if !cfg.raw.Enabled {
		return Accept()
	}

	rules, exists := cfg.kindToRules[event.Kind]
	if !exists {
		return Accept()
	}

	for _, rule := range rules {
		if rule.regex.MatchString(event.Content) {
			slog.Info("Rejecting event due to forbidden keyword/regexp",
				"ip", remoteIP, "pubkey", event.PubKey, "event_id", event.ID,
				"match", rule.source, "rule", rule.description)
			return Reject(fmt.Sprintf("blocked: content contains forbidden content ('%s')", rule.source))
		}
	}

	return Accept()
}

// UpdateConfig implements the UpdatableFilter interface for hot-reloading.
func (f *KeywordFilter) UpdateConfig(newGlobalCfg *config.Config) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	slog.Info("Updating KeywordFilter config...")
	newCfg := &newGlobalCfg.Filters.Keywords

	activeCfg, err := f.buildActiveConfig(newCfg)
	if err != nil {
		return fmt.Errorf("failed to apply new keyword config: %w", err)
	}

	f.activeCfg = activeCfg
	return nil
}

// buildActiveConfig creates a new configuration snapshot with compiled rules.
func (f *KeywordFilter) buildActiveConfig(cfg *config.KeywordFilterConfig) (*activeKeywordConfig, error) {
	kindMap := make(map[int][]compiledKeywordRule)
	for _, rule := range cfg.Rules {
		// Compile simple words into case-insensitive, whole-word regexps.
		for _, word := range rule.Words {
			compiled, err := regexp.Compile(`(?i)\b` + regexp.QuoteMeta(word) + `\b`)
			if err != nil {
				slog.Error("Failed to compile keyword", "word", word, "error", err)
				continue
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

		// Compile user-provided regexps as-is.
		for _, rx := range rule.Regexps {
			compiled, err := regexp.Compile(rx)
			if err != nil {
				return nil, fmt.Errorf("failed to compile user regexp '%s': %w", rx, err)
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
	return &activeKeywordConfig{
		raw:         cfg,
		kindToRules: kindMap,
	}, nil
}
