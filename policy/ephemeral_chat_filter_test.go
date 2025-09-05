// policy/ephemeral_chat_filter_test.go
package policy

import (
	"context"
	"testing"
	"time"

	"adresu-plugin/config"
	"adresu-plugin/testutils"

	"github.com/nbd-wtf/go-nostr"
	"github.com/stretchr/testify/require"
)

func baseCfg() *config.EphemeralChatFilterConfig {
	return &config.EphemeralChatFilterConfig{
		Enabled:                true,
		Kinds:                  []int{nostr.KindTextNote},
		MinDelay:               0,
		MaxCapsRatio:           1.0,
		MinLettersForCapsCheck: 1,
		MaxRepeatChars:         10,
		MaxWordLength:          100,
		BlockZalgo:             false,
		CacheSize:              100,
		RateLimitRate:          100,
		RateLimitBurst:         10,
		RequiredPoWOnLimit:     1,
	}
}

func makeEvent(content string) *nostr.Event {
	return testutils.MakeEvent(nostr.KindTextNote, content, testutils.TestPubKey, time.Now())
}

func TestEphemeralChatFilter_Disabled(t *testing.T) {
	cfg := baseCfg()
	cfg.Enabled = false
	filter := NewEphemeralChatFilter(cfg)

	ev := makeEvent("hello")
	res := filter.Check(context.Background(), ev, "1.1.1.1")
	require.Equal(t, ActionAccept, res.Action)
}

func TestEphemeralChatFilter_MinDelay(t *testing.T) {
	cfg := baseCfg()
	cfg.MinDelay = 1 * time.Second
	filter := NewEphemeralChatFilter(cfg)

	ev1 := makeEvent("first")
	res1 := filter.Check(context.Background(), ev1, "1.1.1.1")
	require.Equal(t, ActionAccept, res1.Action)

	ev2 := makeEvent("second")
	res2 := filter.Check(context.Background(), ev2, "1.1.1.1")
	require.Equal(t, ActionReject, res2.Action, "second event too soon should be rejected")
}

func TestEphemeralChatFilter_ExcessiveCaps(t *testing.T) {
	cfg := baseCfg()
	cfg.MaxCapsRatio = 0.5
	cfg.MinLettersForCapsCheck = 5
	filter := NewEphemeralChatFilter(cfg)

	ev := makeEvent("THIS IS SHOUTING MESSAGE")
	res := filter.Check(context.Background(), ev, "1.1.1.1")
	require.Equal(t, ActionReject, res.Action)
	require.Contains(t, res.Message, "capital")
}

func TestEphemeralChatFilter_RepeatedChars(t *testing.T) {
	cfg := baseCfg()
	cfg.MaxRepeatChars = 3
	filter := NewEphemeralChatFilter(cfg)

	ev := makeEvent("heyyyyyy")
	res := filter.Check(context.Background(), ev, "1.1.1.1")
	require.Equal(t, ActionReject, res.Action)
	require.Contains(t, res.Message, "repetition")
}

func TestEphemeralChatFilter_LongWord(t *testing.T) {
	cfg := baseCfg()
	cfg.MaxWordLength = 5
	filter := NewEphemeralChatFilter(cfg)

	ev := makeEvent("supercalifragilisticexpialidocious")
	res := filter.Check(context.Background(), ev, "1.1.1.1")
	require.Equal(t, ActionReject, res.Action)
	require.Contains(t, res.Message, "too long")
}

func TestEphemeralChatFilter_Zalgo(t *testing.T) {
	cfg := baseCfg()
	cfg.BlockZalgo = true
	filter := NewEphemeralChatFilter(cfg)

	// add combining mark (zalgo-like)
	ev := makeEvent("he\u0301llo")
	res := filter.Check(context.Background(), ev, "1.1.1.1")
	require.Equal(t, ActionReject, res.Action)
	require.Contains(t, res.Message, "Zalgo")
}

func TestEphemeralChatFilter_RateLimitAndPoW(t *testing.T) {
	cfg := baseCfg()
	cfg.RateLimitRate = 1
	cfg.RateLimitBurst = 1
	cfg.RequiredPoWOnLimit = 5
	filter := NewEphemeralChatFilter(cfg)

	// first ok
	ev1 := makeEvent("hi")
	res1 := filter.Check(context.Background(), ev1, "1.1.1.1")
	require.Equal(t, ActionAccept, res1.Action)

	// second should be rate limited
	ev2 := makeEvent("again")
	res2 := filter.Check(context.Background(), ev2, "1.1.1.1")
	require.Equal(t, ActionReject, res2.Action)

	// third with fake PoW
	ev3 := makeEvent("pow msg")
	ev3.ID = "00000abc"                           // leading zeros -> difficulty ~20 bits
	ev3.Tags = nostr.Tags{{"nonce", "123", "20"}} // claim difficulty 20
	res3 := filter.Check(context.Background(), ev3, "1.1.1.1")
	require.Equal(t, ActionAccept, res3.Action, "should accept with valid PoW")
}
