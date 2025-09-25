// policy/emergency_filter_test.go
package policy

import (
	"context"
	"testing"
	"time"

	"adresu-plugin/config"
	"adresu-plugin/testutils"
)

func newCfgBase(enabled bool, rate float64, burst int, cache int, ttl time.Duration) *config.EmergencyFilterConfig {
	return &config.EmergencyFilterConfig{
		Enabled:      enabled,
		NewKeysRate:  rate,
		NewKeysBurst: burst,
		CacheSize:    cache,
		TTL:          ttl,
	}
}

func mustAccept(t *testing.T, res *Result) {
	t.Helper()
	if res == nil || res.Action != ActionAccept {
		t.Fatalf("expected Action=accept, got: %+v", res)
	}
}

func mustReject(t *testing.T, res *Result) {
	t.Helper()
	if res == nil || res.Action != ActionReject {
		t.Fatalf("expected Action=reject, got: %+v", res)
	}
	if res.Message == "" {
		t.Fatalf("expected non-empty reject reason, got: %+v", res)
	}
}

func TestEmergencyFilter_DisabledPassThrough(t *testing.T) {
	cfg := newCfgBase(false, 1e9, 1e9, 1, time.Second)
	f := NewEmergencyFilter(cfg)

	ev := testutils.MakeTextNote(testutils.TestPubKey, "hi", time.Now())
	res := f.Check(context.Background(), ev, "203.0.113.42")
	mustAccept(t, res)
}

func TestEmergencyFilter_KnownPubKeyBypassesLimits(t *testing.T) {
	cfg := newCfgBase(true, 1.0, 1, 10_000, 10*time.Second)
	cfg.PerIP.Enabled = true
	cfg.PerIP.Rate = 100
	cfg.PerIP.Burst = 100
	cfg.PerIP.CacheSize = 10_000
	cfg.PerIP.TTL = time.Minute

	f := NewEmergencyFilter(cfg)

	pk := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	ev1 := testutils.MakeTextNote(pk, "first", time.Now())
	ev2 := testutils.MakeTextNote(pk, "second", time.Now())

	mustAccept(t, f.Check(context.Background(), ev1, "198.51.100.10"))

	evOther := testutils.MakeTextNote("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "other", time.Now())
	_ = f.Check(context.Background(), evOther, "198.51.100.11")

	mustAccept(t, f.Check(context.Background(), ev2, "198.51.100.10"))
}

func TestEmergencyFilter_GlobalNewKeyLimit(t *testing.T) {
	cfg := newCfgBase(true, 1.0, 1, 10_000, 10*time.Second)
	cfg.PerIP.Enabled = false

	f := NewEmergencyFilter(cfg)

	ev1 := testutils.MakeTextNote("pk-1-000000000000000000000000000000000000000000000000000000000001", "x", time.Now())
	ev2 := testutils.MakeTextNote("pk-2-000000000000000000000000000000000000000000000000000000000002", "y", time.Now())

	mustAccept(t, f.Check(context.Background(), ev1, "203.0.113.1"))
	mustReject(t, f.Check(context.Background(), ev2, "203.0.113.2"))
}

func TestEmergencyFilter_PerIPNewKeyLimit_NoNormalization(t *testing.T) {
	cfg := newCfgBase(true, 1000.0, 1000, 10_000, 10*time.Second)
	cfg.PerIP.Enabled = true
	cfg.PerIP.Rate = 1.0
	cfg.PerIP.Burst = 1
	cfg.PerIP.CacheSize = 10_000
	cfg.PerIP.TTL = time.Minute

	f := NewEmergencyFilter(cfg)

	ip := "203.0.113.42"
	ev1 := testutils.MakeTextNote("pk-A-00000000000000000000000000000000000000000000000000000000000A", "x", time.Now())
	ev2 := testutils.MakeTextNote("pk-B-00000000000000000000000000000000000000000000000000000000000B", "y", time.Now())

	mustAccept(t, f.Check(context.Background(), ev1, ip))
	mustReject(t, f.Check(context.Background(), ev2, ip))
}

func TestEmergencyFilter_PerIPNormalization_IPv6_64(t *testing.T) {
	cfg := newCfgBase(true, 1000.0, 1000, 10_000, 10*time.Second)
	cfg.PerIP.Enabled = true
	cfg.PerIP.Rate = 1.0
	cfg.PerIP.Burst = 1
	cfg.PerIP.CacheSize = 10_000
	cfg.PerIP.TTL = time.Minute
	cfg.PerIP.IPv6Prefix = 64

	f := NewEmergencyFilter(cfg)

	ip1 := "2001:db8:abcd:1234::1"
	ip2 := "2001:db8:abcd:1234::2"

	ev1 := testutils.MakeTextNote("pk-v6-1-0000000000000000000000000000000000000000000000000000000001", "x", time.Now())
	ev2 := testutils.MakeTextNote("pk-v6-2-0000000000000000000000000000000000000000000000000000000002", "y", time.Now())

	mustAccept(t, f.Check(context.Background(), ev1, ip1))
	mustReject(t, f.Check(context.Background(), ev2, ip2))
}

func TestEmergencyFilter_PerIPNormalization_IPv4_24(t *testing.T) {
	cfg := newCfgBase(true, 1000.0, 1000, 10_000, 10*time.Second)
	cfg.PerIP.Enabled = true
	cfg.PerIP.Rate = 1.0
	cfg.PerIP.Burst = 1
	cfg.PerIP.CacheSize = 10_000
	cfg.PerIP.TTL = time.Minute
	cfg.PerIP.IPv4Prefix = 24

	f := NewEmergencyFilter(cfg)

	ip1 := "203.0.113.1"
	ip2 := "203.0.113.2"

	ev1 := testutils.MakeTextNote("pk-v4-1-0000000000000000000000000000000000000000000000000000000001", "x", time.Now())
	ev2 := testutils.MakeTextNote("pk-v4-2-0000000000000000000000000000000000000000000000000000000002", "y", time.Now())

	mustAccept(t, f.Check(context.Background(), ev1, ip1))
	mustReject(t, f.Check(context.Background(), ev2, ip2))
}
