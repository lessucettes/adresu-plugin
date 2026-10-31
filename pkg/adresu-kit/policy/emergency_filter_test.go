package policy

import (
	"context"
	"runtime"
	"testing"
	"time"

	"fiatjaf.com/nostr"

	"github.com/lessucettes/adresu-plugin/pkg/adresu-kit/config"
)

func emergencyMatch(t *testing.T, filter *EmergencyFilter, pubkey nostr.PubKey, remoteIP string) bool {
	t.Helper()
	res, err := filter.Match(context.Background(), &nostr.Event{Kind: nostr.KindTextNote, PubKey: pubkey}, map[string]any{"remote_ip": remoteIP})
	if err != nil {
		t.Fatal(err)
	}
	return res.Allowed
}

func TestEmergencyFilterLimitsNewPubKeys(t *testing.T) {
	filter, err := NewEmergencyFilter(&config.EmergencyFilterConfig{
		Enabled:      true,
		NewKeysRate:  0.000001,
		NewKeysBurst: 2,
		CacheSize:    100,
		TTL:          time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}

	if !emergencyMatch(t, filter, fixturePubKey(1), "") || !emergencyMatch(t, filter, fixturePubKey(2), "") {
		t.Fatal("new pubkeys within the burst were rejected")
	}
	if emergencyMatch(t, filter, fixturePubKey(3), "") {
		t.Fatal("new pubkey above the burst was allowed")
	}
	if !emergencyMatch(t, filter, fixturePubKey(1), "") {
		t.Fatal("recently seen pubkey was counted as new again")
	}
}

func TestEmergencyFilterLimitsPerIP(t *testing.T) {
	cfg := &config.EmergencyFilterConfig{
		Enabled:      true,
		NewKeysRate:  1000,
		NewKeysBurst: 50,
		CacheSize:    100,
		TTL:          time.Minute,
	}
	cfg.PerIP.Enabled = true
	cfg.PerIP.Rate = 0.000001
	cfg.PerIP.Burst = 1
	cfg.PerIP.CacheSize = 100
	cfg.PerIP.TTL = time.Minute

	filter, err := NewEmergencyFilter(cfg)
	if err != nil {
		t.Fatal(err)
	}

	if !emergencyMatch(t, filter, fixturePubKey(0x0a), "198.51.100.7") {
		t.Fatal("first new pubkey from an IP was rejected")
	}
	if emergencyMatch(t, filter, fixturePubKey(0x0b), "198.51.100.7") {
		t.Fatal("second new pubkey from the same IP was allowed")
	}
	if !emergencyMatch(t, filter, fixturePubKey(0x0c), "198.51.100.8") {
		t.Fatal("new pubkey from another IP was rejected")
	}
}

func TestNormalizeIPWithOptionalPrefixes(t *testing.T) {
	cases := []struct {
		ip       string
		v4Prefix int
		v6Prefix int
		want     string
	}{
		{"192.168.1.77", 0, 0, "192.168.1.77"},
		{"192.168.1.77", 24, 0, "192.168.1.0/24"},
		{"::ffff:192.168.1.77", 24, 0, "192.168.1.0/24"},
		{"2001:db8::1", 0, 0, "2001:db8::1"},
		{"2001:db8::1", 0, 64, "2001:db8::/64"},
		{"not-an-ip", 24, 64, "not-an-ip"},
	}

	for _, tc := range cases {
		if got := normalizeIPWithOptionalPrefixes(tc.ip, tc.v4Prefix, tc.v6Prefix); got != tc.want {
			t.Errorf("normalizeIPWithOptionalPrefixes(%q, %d, %d) = %q, want %q", tc.ip, tc.v4Prefix, tc.v6Prefix, got, tc.want)
		}
	}
}

// Each expirable cache used to start an immortal goroutine, so rebuilding
// filters on every configuration reload leaked two goroutines per filter.
func TestEmergencyFiltersDoNotStartGoroutines(t *testing.T) {
	runtime.GC()
	before := runtime.NumGoroutine()

	filters := make([]*EmergencyFilter, 0, 50)
	for i := 0; i < 50; i++ {
		cfg := &config.EmergencyFilterConfig{
			Enabled:      true,
			NewKeysRate:  1,
			NewKeysBurst: 1,
			CacheSize:    10,
			TTL:          time.Minute,
		}
		cfg.PerIP.Enabled = true
		cfg.PerIP.Rate = 1
		cfg.PerIP.Burst = 1
		cfg.PerIP.CacheSize = 10
		cfg.PerIP.TTL = time.Minute

		filter, err := NewEmergencyFilter(cfg)
		if err != nil {
			t.Fatal(err)
		}
		filters = append(filters, filter)
	}

	if after := runtime.NumGoroutine(); after > before+2 {
		t.Fatalf("goroutines grew from %d to %d after creating 50 filters", before, after)
	}
	runtime.KeepAlive(filters)
}
