package policy

import (
	"context"
	"net"
	"sync"

	"fiatjaf.com/nostr"
	"golang.org/x/time/rate"

	"github.com/lessucettes/adresu-plugin/pkg/adresu-kit/cache"
	"github.com/lessucettes/adresu-plugin/pkg/adresu-kit/config"
)

const (
	emergencyFilterName = "EmergencyFilter"
)

type EmergencyFilter struct {
	mu            sync.Mutex
	newKeyLimiter *rate.Limiter
	recentSeen    *cache.LRU[nostr.PubKey, struct{}]

	perIPEnabled  bool
	perIPLimiters *cache.LRU[string, *rate.Limiter]
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
		recentSeen:    cache.NewLRU[nostr.PubKey, struct{}](cfg.CacheSize, cfg.TTL),
	}

	if cfg.PerIP.Enabled {
		filter.perIPEnabled = true
		filter.perIPLimiters = cache.NewLRU[string, *rate.Limiter](cfg.PerIP.CacheSize, cfg.PerIP.TTL)
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
		return newResult(true, "Filter is disabled.", nil)
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	pk := authorKey(ev)
	if pk == nostr.ZeroPK {
		return newResult(true, "Event has no public key; new-key rate check was skipped.", nil)
	}
	if _, ok := f.recentSeen.Get(pk); ok {
		return newResult(true, "Public key was recently seen and does not count as new.", nil)
	}

	if f.perIPEnabled {
		if remoteIP, ok := meta["remote_ip"].(string); ok && remoteIP != "" {
			key := normalizeIPWithOptionalPrefixes(remoteIP, f.ipv4Prefix, f.ipv6Prefix)

			lim, ok := f.perIPLimiters.Get(key)
			if !ok {
				lim = rate.NewLimiter(f.perIPRate, f.perIPBurst)
			}
			f.perIPLimiters.Add(key, lim)

			if !lim.Allow() {
				return newResult(false, "Rate limit for new public keys from this IP address or network exceeded.", nil)
			}
		}
	}

	if !f.newKeyLimiter.Allow() {
		return newResult(false, "Relay-wide rate limit for new public keys exceeded.", nil)
	}

	f.recentSeen.Add(pk, struct{}{})
	return newResult(true, "New public key is within the allowed rate limits.", nil)
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
