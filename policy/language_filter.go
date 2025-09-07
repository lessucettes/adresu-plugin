// policy/language_filter.go
package policy

import (
	"adresu-plugin/config"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/nbd-wtf/go-nostr"
	"github.com/pemistahl/lingua-go"
)

var (
	globalDetectorOnce sync.Once
	globalDetector     lingua.LanguageDetector
	buildLookupOnce    sync.Once
	languageLookupMap  map[string]lingua.Language
)

// SafeApprovedCache wraps expirable LRU with a RWMutex since it is not goroutine-safe.
type SafeApprovedCache struct {
	mu    sync.RWMutex
	cache *lru.LRU[string, struct{}]
}

// NewSafeApprovedCache now correctly accepts time.Duration for consistency.
func NewSafeApprovedCache(size int, ttl time.Duration) *SafeApprovedCache {
	return &SafeApprovedCache{
		cache: lru.NewLRU[string, struct{}](size, nil, ttl),
	}
}

func (c *SafeApprovedCache) Get(key string) (struct{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cache.Get(key)
}

// Add is now correctly implemented with a single lock for the entire operation.
func (c *SafeApprovedCache) Add(key string, value struct{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache.Add(key, value)
}

type LanguageFilter struct {
	cfg               *config.LanguageFilterConfig
	detector          lingua.LanguageDetector
	allowedLangs      map[lingua.Language]struct{}
	allowedKinds      map[int]struct{}
	approvedCache     *SafeApprovedCache
	thresholds        map[lingua.Language]map[lingua.Language]float64
	defaultThresholds map[lingua.Language]float64
}

func NewLanguageFilter(cfg *config.LanguageFilterConfig, detector lingua.LanguageDetector) *LanguageFilter {
	if !cfg.Enabled {
		return &LanguageFilter{cfg: cfg}
	}
	if detector == nil {
		panic("language filter enabled but detector is nil")
	}

	buildLookupOnce.Do(buildLanguageLookupMap)

	// --- Standard setup (Allowed Languages & Kinds) ---
	allowedMap := make(map[lingua.Language]struct{}, len(cfg.AllowedLanguages))
	for _, langStr := range cfg.AllowedLanguages {
		if lang, ok := languageLookupMap[strings.ToLower(langStr)]; ok {
			allowedMap[lang] = struct{}{}
		} else {
			slog.Warn("Unsupported language name or ISO code in config; ignored", "lang", langStr)
		}
	}

	allowedKinds := make(map[int]struct{}, len(cfg.KindsToCheck))
	for _, k := range cfg.KindsToCheck {
		allowedKinds[k] = struct{}{}
	}

	// --- NEW: Pre-processing threshold rules from config ---
	thresholds := make(map[lingua.Language]map[lingua.Language]float64)
	defaultThresholds := make(map[lingua.Language]float64)

	for primaryStr, similarMap := range cfg.PrimaryAcceptThreshold {
		primaryLang, ok := languageLookupMap[strings.ToLower(primaryStr)]
		if !ok {
			// This is a safeguard; validation in config.go should prevent this.
			slog.Error("Primary language in threshold rules not found, skipping rule.", "lang", primaryStr)
			continue
		}

		thresholds[primaryLang] = make(map[lingua.Language]float64)
		for similarStr, confidence := range similarMap {
			if strings.ToLower(similarStr) == "default" {
				defaultThresholds[primaryLang] = confidence
			} else if similarLang, ok := languageLookupMap[strings.ToLower(similarStr)]; ok {
				thresholds[primaryLang][similarLang] = confidence
			} else {
				slog.Warn("Unsupported similar language in threshold rule; ignored", "primary", primaryStr, "similar", similarStr)
			}
		}
	}

	var cache *SafeApprovedCache
	if cfg.ApprovedCacheTTL > 0 && cfg.ApprovedCacheSize > 0 {
		cache = NewSafeApprovedCache(cfg.ApprovedCacheSize, cfg.ApprovedCacheTTL)
	}

	return &LanguageFilter{
		cfg:               cfg,
		detector:          detector,
		allowedLangs:      allowedMap,
		allowedKinds:      allowedKinds,
		approvedCache:     cache,
		thresholds:        thresholds,
		defaultThresholds: defaultThresholds,
	}
}

func (f *LanguageFilter) Name() string { return "LanguageFilter" }

func (f *LanguageFilter) Check(ctx context.Context, event *nostr.Event, remoteIP string) *Result {
	// --- Step 1-4: Fast exit checks (unchanged) ---
	if !f.cfg.Enabled || len(f.allowedLangs) == 0 {
		return Accept()
	}
	if _, ok := f.allowedKinds[event.Kind]; !ok {
		return Accept()
	}

	if f.cfg.MinLengthForCheck > 0 && len(event.Content) < f.cfg.MinLengthForCheck {
		return Accept()
	}
	if f.approvedCache != nil {
		if _, ok := f.approvedCache.Get(event.PubKey); ok {
			return Accept()
		}
	}

	// --- Step 5: Main logic ---
	detectedLang, detected := f.detector.DetectLanguageOf(event.Content)
	if !detected {
		return Reject("blocked: language could not be determined")
	}

	// --- Step 5.1: Check if the detected language is in the main allow list ---
	if _, isAllowed := f.allowedLangs[detectedLang]; isAllowed {
		if f.approvedCache != nil {
			f.approvedCache.Add(event.PubKey, struct{}{})
		}
		return Accept()
	}

	// --- Step 5.2 : If not directly allowed, check confidence against primary languages ---
	for primaryLang, similarLangsMap := range f.thresholds {
		// Find the threshold: first for the specific detected language, then for "default".
		threshold, hasRule := similarLangsMap[detectedLang]
		if !hasRule {
			threshold, hasRule = f.defaultThresholds[primaryLang]
		}

		// If a rule exists for this primary/detected pair...
		if hasRule {
			// ...compute confidence only when necessary.
			confidence := f.detector.ComputeLanguageConfidence(event.Content, primaryLang)
			if confidence > threshold {
				// The old slog.Debug call is removed.
				if f.approvedCache != nil {
					f.approvedCache.Add(event.PubKey, struct{}{})
				}
				return Accept()
			}
		}
	}

	// --- Step 6: Reject if no rule was met ---
	return Reject(
		fmt.Sprintf("blocked: language '%s' is not allowed", detectedLang.String()),
		slog.String("detected_language", detectedLang.String()),
	)
}

// --- Helpers ---

func GetGlobalDetector() lingua.LanguageDetector {
	globalDetectorOnce.Do(func() {
		slog.Info("Building language detector models...")
		globalDetector = lingua.NewLanguageDetectorBuilder().
			FromAllLanguages().
			WithPreloadedLanguageModels().
			Build()
	})
	return globalDetector
}

func buildLanguageLookupMap() {
	allLangs := lingua.AllLanguages()
	languageLookupMap = make(map[string]lingua.Language, len(allLangs)*3)

	for _, lang := range allLangs {
		languageLookupMap[strings.ToLower(lang.String())] = lang
		languageLookupMap[strings.ToLower(lang.IsoCode639_1().String())] = lang
		languageLookupMap[strings.ToLower(lang.IsoCode639_3().String())] = lang
	}
}
