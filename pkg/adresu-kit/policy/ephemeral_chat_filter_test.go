package policy

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"

	"github.com/lessucettes/adresu-plugin/pkg/adresu-kit/config"
)

const ephemeralChatKind = 20000

func newEphemeralChatFilter(t *testing.T, cfg *config.EphemeralChatFilterConfig) *EphemeralChatFilter {
	t.Helper()
	filter, err := NewEphemeralChatFilter(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return filter
}

func ephemeralChatConfig() *config.EphemeralChatFilterConfig {
	return &config.EphemeralChatFilterConfig{
		Enabled:            true,
		Kinds:              []int{ephemeralChatKind},
		MaxCapsRatio:       0,
		MaxRepeatChars:     0,
		MaxWordLength:      1000,
		BlockZalgo:         false,
		CacheSize:          100,
		RateLimitRate:      0.000001,
		RateLimitBurst:     1,
		RequiredPoWOnLimit: 8,
	}
}

func TestEphemeralChatRateLimitAcceptsPoW(t *testing.T) {
	filter := newEphemeralChatFilter(t, ephemeralChatConfig())

	event := &nostr.Event{Kind: ephemeralChatKind, PubKey: "pk-1", Content: "hello"}
	if res, err := filter.Match(context.Background(), event, nil); err != nil || !res.Allowed {
		t.Fatalf("first message = (%v, %v), want allowed", res, err)
	}
	if res, err := filter.Match(context.Background(), event, nil); err != nil || res.Allowed {
		t.Fatalf("second message = (%v, %v), want rate-limited", res, err)
	}

	withPoW := ephemeralPoWEvent(t)
	if res, err := filter.Match(context.Background(), withPoW, nil); err != nil || !res.Allowed {
		t.Fatalf("PoW message = (%v, %v), want allowed", res, err)
	}
}

// ephemeralPoWEvent mines a correctly hashed event with an ID that has at
// least 8 leading zero bits and a matching NIP-13 nonce tag.
func ephemeralPoWEvent(t *testing.T) *nostr.Event {
	t.Helper()

	event := &nostr.Event{
		Kind:    ephemeralChatKind,
		PubKey:  "pk-1",
		Content: "hello",
		Tags:    nostr.Tags{{"nonce", "0", "8"}},
	}
	for nonce := 0; nonce < 100000; nonce++ {
		event.Tags[0][1] = strconv.Itoa(nonce)
		id := event.GetID()
		if strings.HasPrefix(id, "00") {
			event.ID = id
			return event
		}
	}
	t.Fatal("failed to mine an event with 8 leading zero bits")
	return nil
}

func TestEphemeralChatContentThresholds(t *testing.T) {
	for _, tc := range []struct {
		name, content       string
		minLetters, repeats int
		allowed             bool
	}{
		{"below_caps_minimum", "AAAA", 5, 0, true},
		{"at_caps_minimum", "AAAAA", 5, 0, false},
		{"repeat_one_single_character", "a", 20, 1, true},
		{"repeat_one_distinct_characters", "ab", 20, 1, true},
		{"repeat_one_actual_repeat", "aa", 20, 1, false},
		{"below_repeat_threshold", "aab", 20, 3, true},
		{"at_repeat_threshold", "aaa", 20, 3, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := ephemeralChatConfig()
			cfg.MaxCapsRatio = 0.5
			cfg.MinLettersForCapsCheck = tc.minLetters
			cfg.MaxRepeatChars = tc.repeats
			f := newEphemeralChatFilter(t, cfg)
			res, err := f.Match(context.Background(), &nostr.Event{Kind: ephemeralChatKind, PubKey: "author", Content: tc.content}, nil)
			if err != nil || res.Allowed != tc.allowed {
				t.Fatalf("Allowed=%v error=%v, want Allowed=%v (reason: %s)", res.Allowed, err, tc.allowed, res.Reason)
			}
		})
	}
}

func TestEphemeralChatMinDelay(t *testing.T) {
	cfg := ephemeralChatConfig()
	cfg.MinDelay = 100 * time.Millisecond
	cfg.RateLimitBurst = 10
	filter := newEphemeralChatFilter(t, cfg)

	event := &nostr.Event{Kind: ephemeralChatKind, PubKey: "pk-1", Content: "hello"}
	if res, err := filter.Match(context.Background(), event, nil); err != nil || !res.Allowed {
		t.Fatalf("first message = (%v, %v), want allowed", res, err)
	}
	if res, err := filter.Match(context.Background(), event, nil); err != nil || res.Allowed {
		t.Fatalf("message inside min_delay = (%v, %v), want rejected", res, err)
	}

	time.Sleep(150 * time.Millisecond)
	if res, err := filter.Match(context.Background(), event, nil); err != nil || !res.Allowed {
		t.Fatalf("message after min_delay = (%v, %v), want allowed", res, err)
	}
}
