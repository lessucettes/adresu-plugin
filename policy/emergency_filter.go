// policy/emergency_filter.go
package policy

import (
	"context"
	"net"
	"time"

	lru "github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/nbd-wtf/go-nostr"
	"golang.org/x/time/rate"

	"adresu-plugin/config"
)

type EmergencyFilter struct {
	enabled bool

	newKeyLimiter *rate.Limiter
	recentSeen    *lru.LRU[string, struct{}]

	perIPEnabled  bool
	perIPLimiters *lru.LRU[string, *rate.Limiter]
	perIPRate     rate.Limit
	perIPBurst    int
	perIPTTL      time.Duration

	ipv4Prefix int
	ipv6Prefix int
}

func NewEmergencyFilter(cfg *config.EmergencyFilterConfig) *EmergencyFilter {
	if cfg == nil || !cfg.Enabled {
		return &EmergencyFilter{enabled: false}
	}
	ttl := cfg.TTL
	size := cfg.CacheSize
	ef := &EmergencyFilter{
		enabled:       true,
		newKeyLimiter: rate.NewLimiter(rate.Limit(cfg.NewKeysRate), cfg.NewKeysBurst),
		recentSeen:    lru.NewLRU[string, struct{}](size, nil, ttl),
	}

	if cfg.PerIP.Enabled {
		ipTTL := cfg.PerIP.TTL
		ipSize := cfg.PerIP.CacheSize
		ef.perIPEnabled = true
		ef.perIPLimiters = lru.NewLRU[string, *rate.Limiter](ipSize, nil, ipTTL)
		ef.perIPRate = rate.Limit(cfg.PerIP.Rate)
		ef.perIPBurst = cfg.PerIP.Burst
		ef.perIPTTL = ipTTL

		ef.ipv4Prefix = cfg.PerIP.IPv4Prefix // 0 => off
		ef.ipv6Prefix = cfg.PerIP.IPv6Prefix // 0 => off
	}

	return ef
}

func (f *EmergencyFilter) Name() string { return "EmergencyFilter" }

func (f *EmergencyFilter) Check(ctx context.Context, ev *nostr.Event, remoteIP string) *Result {
	_ = ctx

	if !f.enabled {
		return Accept()
	}
	pk := ev.PubKey
	if pk == "" {
		return Accept()
	}
	if _, ok := f.recentSeen.Get(pk); ok {
		return Accept()
	}

	if f.perIPEnabled && remoteIP != "" {
		key := normalizeIPWithOptionalPrefixes(remoteIP, f.ipv4Prefix, f.ipv6Prefix)
		if lim, ok := f.perIPLimiters.Get(key); ok && lim != nil {
			if !lim.Allow() {
				return Reject("blocked: emergency per-ip limit for new pubkeys exceeded")
			}
		} else {
			lim := rate.NewLimiter(f.perIPRate, f.perIPBurst)
			f.perIPLimiters.Add(key, lim)
			if !lim.Allow() {
				return Reject("blocked: emergency per-ip limit for new pubkeys exceeded")
			}
		}
	}

	if !f.newKeyLimiter.Allow() {
		return Reject("blocked: emergency global limit for new pubkeys exceeded")
	}

	f.recentSeen.Add(pk, struct{}{})
	return Accept()
}

func normalizeIPWithOptionalPrefixes(ipStr string, v4Prefix, v6Prefix int) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ipStr
	}
	if v4 := ip.To4(); v4 != nil {
		if v4Prefix > 0 {
			return (&net.IPNet{
				IP:   v4.Mask(net.CIDRMask(v4Prefix, 32)),
				Mask: net.CIDRMask(v4Prefix, 32),
			}).String()
		}
		return v4.String()
	}
	if v6Prefix > 0 {
		return (&net.IPNet{
			IP:   ip.Mask(net.CIDRMask(v6Prefix, 128)),
			Mask: net.CIDRMask(v6Prefix, 128),
		}).String()
	}
	return ip.String()
}
