package policy

import (
	"testing"

	"github.com/lessucettes/adresu-plugin/pkg/adresu-kit/config"
	"github.com/pemistahl/lingua-go"
)

func TestLanguageFilterRequiresSupportedAllowedLanguage(t *testing.T) {
	detector := lingua.NewLanguageDetectorBuilder().FromLanguages(lingua.English, lingua.German).Build()
	cfg := &config.LanguageFilterConfig{Enabled: true, AllowedLanguages: []string{"not-a-language"}, KindsToCheck: []int{1}}
	if _, err := NewLanguageFilter(cfg, detector); err == nil {
		t.Fatal("enabled filter silently accepts all content when no configured language is supported")
	}
	cfg.AllowedLanguages = append(cfg.AllowedLanguages, "en")
	if _, err := NewLanguageFilter(cfg, detector); err != nil {
		t.Fatalf("a supported language mixed with an ignored unknown entry must still work: %v", err)
	}
}
