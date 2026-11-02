package policy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"

	"fiatjaf.com/nostr"
	"github.com/pemistahl/lingua-go"

	"github.com/lessucettes/adresu-plugin/pkg/adresu-kit/cache"
	"github.com/lessucettes/adresu-plugin/pkg/adresu-kit/config"
)

var (
	globalDetectorOnce  sync.Once
	globalDetector      lingua.LanguageDetector
	buildLookupOnce     sync.Once
	languageLookupMap   map[string]lingua.Language
	contentCleanerRegex *regexp.Regexp
)

const (
	languageFilterName = "LanguageFilter"
)

func init() {
	const cleanerPattern = `((https?|wss?)://|www\.|ww\.)[^\s/?.#-]+\S*|[a-zA-Z0-9.!$%&’+_\x60\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,64}|nostr:[a-z0-9]+|#\S+|[a-zA-Z]*[0-9]+[a-zA-Z0-9]*`
	contentCleanerRegex = regexp.MustCompile(cleanerPattern)
}

type LanguageFilter struct {
	cfg               *config.LanguageFilterConfig
	detector          lingua.LanguageDetector
	allowedLangs      map[lingua.Language]struct{}
	allowedKinds      map[int]struct{}
	approvedCache     *cache.LRU[nostr.PubKey, struct{}]
	thresholds        map[lingua.Language]map[lingua.Language]float64
	defaultThresholds map[lingua.Language]float64
}

func NewLanguageFilter(cfg *config.LanguageFilterConfig, detector lingua.LanguageDetector) (*LanguageFilter, error) {
	if !cfg.Enabled {
		return &LanguageFilter{cfg: cfg}, nil
	}
	if detector == nil {
		return nil, errors.New("language filter enabled but detector is nil")
	}

	buildLookupOnce.Do(buildLanguageLookupMap)

	allowedMap := make(map[lingua.Language]struct{}, len(cfg.AllowedLanguages))
	for _, langStr := range cfg.AllowedLanguages {
		if lang, ok := languageLookupMap[strings.ToLower(langStr)]; ok {
			allowedMap[lang] = struct{}{}
		} else {
			slog.Warn("LanguageFilter config warning: unsupported language name or ISO code in config; ignored", "value", langStr)
		}
	}
	if len(allowedMap) == 0 {
		return nil, errors.New("language filter enabled but no allowed language is supported")
	}

	allowedKinds := make(map[int]struct{}, len(cfg.KindsToCheck))
	for _, k := range cfg.KindsToCheck {
		allowedKinds[k] = struct{}{}
	}

	thresholds := make(map[lingua.Language]map[lingua.Language]float64)
	defaultThresholds := make(map[lingua.Language]float64)

	for primaryStr, similarMap := range cfg.PrimaryAcceptThreshold {
		primaryLang, ok := languageLookupMap[strings.ToLower(primaryStr)]
		if !ok {
			slog.Warn("LanguageFilter config warning: primary language in threshold rules not found, skipping rule", "language", primaryStr)
			continue
		}
		thresholds[primaryLang] = make(map[lingua.Language]float64)
		for similarStr, confidence := range similarMap {
			if strings.ToLower(similarStr) == "default" {
				defaultThresholds[primaryLang] = confidence
			} else if similarLang, ok := languageLookupMap[strings.ToLower(similarStr)]; ok {
				thresholds[primaryLang][similarLang] = confidence
			} else {
				slog.Warn("LanguageFilter config warning: unsupported similar language in threshold rule; ignored", "primary", primaryStr, "similar", similarStr)
			}
		}
	}

	var cacheStore *cache.LRU[nostr.PubKey, struct{}]
	if cfg.ApprovedCacheTTL > 0 && cfg.ApprovedCacheSize > 0 {
		cacheStore = cache.NewLRU[nostr.PubKey, struct{}](cfg.ApprovedCacheSize, cfg.ApprovedCacheTTL)
	}

	filter := &LanguageFilter{
		cfg:               cfg,
		detector:          detector,
		allowedLangs:      allowedMap,
		allowedKinds:      allowedKinds,
		approvedCache:     cacheStore,
		thresholds:        thresholds,
		defaultThresholds: defaultThresholds,
	}

	return filter, nil
}

func (f *LanguageFilter) Match(_ context.Context, event *nostr.Event, meta map[string]any) (FilterResult, error) {
	newResult := NewResultFunc(languageFilterName)

	if !f.cfg.Enabled || len(f.allowedLangs) == 0 {
		return newResult(true, "Filter is disabled.", nil)
	}
	if _, ok := f.allowedKinds[int(event.Kind)]; !ok {
		return newResult(true, "Language check does not apply to this event kind.", nil)
	}
	if f.cfg.MinLengthForCheck > 0 && len(event.Content) < f.cfg.MinLengthForCheck {
		return newResult(true, "Content is too short for language detection; check was skipped.", nil)
	}
	if f.approvedCache != nil {
		if _, ok := f.approvedCache.Get(event.PubKey); ok {
			return newResult(true, "Author has a cached language approval; check was skipped.", nil)
		}
	}

	cleanedContent := contentCleanerRegex.ReplaceAllString(event.Content, "")
	if len(cleanedContent) < f.cfg.MinLengthForCheck {
		return newResult(true, "Content is too short for language detection after cleaning; check was skipped.", nil)
	}

	detectedLang, detected := f.detector.DetectLanguageOf(cleanedContent)
	if !detected {
		return newResult(false, "Content language could not be detected.", nil)
	}

	langName := detectedLang.String()
	if _, isAllowed := f.allowedLangs[detectedLang]; isAllowed {
		if f.approvedCache != nil {
			f.approvedCache.Add(event.PubKey, struct{}{})
		}
		if meta != nil {
			meta["language"] = langName
		}
		return newResult(true, fmt.Sprintf("Detected language %q is allowed on this relay.", langName), nil)
	}

	for primaryLang, similarLangsMap := range f.thresholds {
		threshold, hasRule := similarLangsMap[detectedLang]
		if !hasRule {
			threshold, hasRule = f.defaultThresholds[primaryLang]
		}
		if hasRule {
			if confidence := f.detector.ComputeLanguageConfidence(cleanedContent, primaryLang); confidence > threshold {
				if f.approvedCache != nil {
					f.approvedCache.Add(event.PubKey, struct{}{})
				}
				if meta != nil {
					meta["language"] = langName
				}
				primaryLangName := primaryLang.String()
				return newResult(true, fmt.Sprintf("Detected language %q is accepted because confidence for allowed language %q exceeds its threshold.", langName, primaryLangName), nil)
			}
		}
	}

	return newResult(false, fmt.Sprintf("Detected language %q is not allowed on this relay.", langName), nil)
}

func GetGlobalDetector() lingua.LanguageDetector {
	globalDetectorOnce.Do(func() {
		globalDetector = lingua.NewLanguageDetectorBuilder().
			FromAllLanguages().
			WithLowAccuracyMode().
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
