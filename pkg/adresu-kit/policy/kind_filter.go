package policy

import (
	"context"
	"fmt"

	"github.com/nbd-wtf/go-nostr"

	"github.com/lessucettes/adresu-plugin/pkg/adresu-kit/config"
)

const (
	kindFilterName = "KindFilter"
)

type KindFilter struct {
	allowed, denied map[int]struct{}
}

func NewKindFilter(cfg *config.KindFilterConfig) (*KindFilter, error) {
	deniedMap := make(map[int]struct{}, len(cfg.DeniedKinds))
	for _, kind := range cfg.DeniedKinds {
		deniedMap[kind] = struct{}{}
	}

	var allowedMap map[int]struct{}
	if len(cfg.AllowedKinds) > 0 {
		allowedMap = make(map[int]struct{}, len(cfg.AllowedKinds))
		for _, kind := range cfg.AllowedKinds {
			allowedMap[kind] = struct{}{}
		}
	}

	filter := &KindFilter{
		allowed: allowedMap,
		denied:  deniedMap,
	}

	return filter, nil
}

func (f *KindFilter) Match(_ context.Context, event *nostr.Event, meta map[string]any) (FilterResult, error) {
	newResult := NewResultFunc(kindFilterName)

	if _, isDenied := f.denied[event.Kind]; isDenied {
		return newResult(false, fmt.Sprintf("kind_%d_denied", event.Kind), nil)
	}

	if f.allowed != nil {
		if _, isAllowed := f.allowed[event.Kind]; !isAllowed {
			return newResult(false, fmt.Sprintf("kind_%d_not_allowed", event.Kind), nil)
		}
	}

	return newResult(true, "kind_allowed", nil)
}
