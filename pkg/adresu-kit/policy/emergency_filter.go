package policy

import (
	"context"
	"net"

	lru "github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/nbd-wtf/go-nostr"
	"golang.org/x/time/rate"

	"github.com/lessucettes/adresu-plugin/pkg/adresu-kit/config"
)

const (
	emergencyFilterName = "EmergencyFilter"
)

type EmergencyFilter struct {
	newKeyLimiter *rate.Limiter
	recentSeen    *lru.LRU[string, struct{}]

	perIPEnabled  bool
	perIPLimiters *lru.LRU[string, *rate.Limiter]
	perIPRate     rate.Limit
	perIPBurst    int

	ipv4Prefix int
	ipv6Prefix int
}

func NewEmergencyFilter(cfg *config.EmergencyFilterConfig) (*EmergencyFilter, error) {
	if cfg == nil || !cfg.Enabled {
		return &EmergencyFilter{}, nil
	}

	filter := &EmergencyFilter{
		newKeyLimiter: rate.NewLimiter(rate.Limit(cfg.NewKeysRate), cfg.NewKeysBurst),
		recentSeen:    lru.NewLRU[string, struct{}](cfg.CacheSize, nil, cfg.TTL),
	}

	if cfg.PerIP.Enabled {
		filter.perIPEnabled = true
		filter.perIPLimiters = lru.NewLRU[string, *rate.Limiter](cfg.PerIP.CacheSize, nil, cfg.PerIP.TTL)
		filter.perIPRate = rate.Limit(cfg.PerIP.Rate)
		filter.perIPBurst = cfg.PerIP.Burst
		filter.ipv4Prefix = cfg.PerIP.IPv4Prefix
		filter.ipv6Prefix = cfg.PerIP.IPv6Prefix
	}

	return filter, nil
}

func (f *EmergencyFilter) Match(_ context.Context, ev *nostr.Event, meta map[string]any) (FilterResult, error) {
	newResult := NewResultFunc(emergencyFilterName)

	if f.newKeyLimiter == nil {
		return newResult(true, "filter_disabled", nil)
	}

	pk := ev.PubKey
	if pk == "" {
		return newResult(true, "pubkey_empty", nil)
	}
	if _, ok := f.recentSeen.Get(pk); ok {
		return newResult(true, "pubkey_recently_seen", nil)
	}

	if f.perIPEnabled {
		if remoteIP, ok := meta["remote_ip"].(string); ok && remoteIP != "" {
			key := normalizeIPWithOptionalPrefixes(remoteIP, f.ipv4Prefix, f.ipv6Prefix)

			lim, ok := f.perIPLimiters.Get(key)
			if !ok {
				lim = rate.NewLimiter(f.perIPRate, f.perIPBurst)
				f.perIPLimiters.Add(key, lim)
			}

			if !lim.Allow() {
				return newResult(false, "new_pubkey_rate_limit_exceeded_per_ip", nil)
			}
		}
	}

	if !f.newKeyLimiter.Allow() {
		return newResult(false, "new_pubkey_rate_limit_exceeded_global", nil)
	}

	f.recentSeen.Add(pk, struct{}{})
	return newResult(true, "new_pubkey_accepted", nil)
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
