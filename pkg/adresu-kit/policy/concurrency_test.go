package policy

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lessucettes/adresu-plugin/pkg/adresu-kit/config"
	"github.com/nbd-wtf/go-nostr"
)

func TestConcurrentRateAdmission(t *testing.T) {
	factories := map[string]func() (Filter, error){
		"global": func() (Filter, error) {
			return NewRateLimiterFilter(&config.RateLimiterConfig{Enabled: true, By: config.RateByPubKey, DefaultRate: 0.000001, DefaultBurst: 1})
		},
		"ephemeral_rate": func() (Filter, error) {
			return NewEphemeralChatFilter(ephemeralChatConfig())
		},
		"ephemeral_delay": func() (Filter, error) {
			cfg := ephemeralChatConfig()
			cfg.MinDelay = time.Hour
			cfg.RateLimitBurst = 1000
			return NewEphemeralChatFilter(cfg)
		},
		"emergency_ip": func() (Filter, error) {
			cfg := &config.EmergencyFilterConfig{Enabled: true, NewKeysRate: 1000, NewKeysBurst: 1000, CacheSize: 1000, TTL: time.Hour}
			cfg.PerIP.Enabled = true
			cfg.PerIP.Rate = 0.000001
			cfg.PerIP.Burst = 1
			cfg.PerIP.CacheSize = 1000
			cfg.PerIP.TTL = time.Hour
			return NewEmergencyFilter(cfg)
		},
	}
	for name, factory := range factories {
		t.Run(name, func(t *testing.T) {
			for round := 0; round < 32; round++ {
				filter, err := factory()
				if err != nil {
					t.Fatal(err)
				}
				var accepted atomic.Int32
				var wg sync.WaitGroup
				start := make(chan struct{})
				for i := 0; i < 64; i++ {
					wg.Add(1)
					go func(i int) {
						defer wg.Done()
						<-start
						pubkey := "same-author"
						if name == "emergency_ip" {
							pubkey = fmt.Sprintf("author-%d", i)
						}
						res, err := filter.Match(context.Background(), &nostr.Event{Kind: ephemeralChatKind, PubKey: pubkey}, map[string]any{"remote_ip": "127.0.0.1"})
						if err != nil {
							t.Errorf("Match: %v", err)
						}
						if res.Allowed {
							accepted.Add(1)
						}
					}(i)
				}
				close(start)
				wg.Wait()
				if got := accepted.Load(); got != 1 {
					t.Fatalf("round %d: admitted %d concurrent events, want exactly 1", round, got)
				}
			}
		})
	}
}
