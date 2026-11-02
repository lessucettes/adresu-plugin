package reputation

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// discoveryDialOptions is the narrow test seam for discovered relays. Tests
// may substitute DNS answers and the final connection, but URL validation and
// the public-address guard always run before dial.
type discoveryDialOptions struct {
	resolve   func(context.Context, string) ([]net.IP, error)
	dial      func(context.Context, string, string) (net.Conn, error)
	tlsConfig *tls.Config
}

// newDiscoveryClient builds the only HTTP client used for NIP-65-discovered
// relays. Proxy support is deliberately absent: an HTTP(S)_PROXY environment
// variable must not reroute these connections. Redirects are errors, and the
// dialer resolves and validates the address it actually connects to.
func newDiscoveryClient(opts discoveryDialOptions) *http.Client {
	if opts.resolve == nil {
		opts.resolve = lookupPublicHost
	}
	if opts.dial == nil {
		dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
		opts.dial = dialer.DialContext
	}
	tlsConfig := opts.tlsConfig
	if tlsConfig == nil {
		tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		tlsConfig = tlsConfig.Clone()
		tlsConfig.MinVersion = tls.VersionTLS12
	}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialPublicAddress(ctx, network, addr, opts)
		},
		TLSClientConfig:       tlsConfig,
		ForceAttemptHTTP2:     false,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		MaxIdleConns:          maxDiscoveryConcurrency,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       90 * time.Second,
	}
	return &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("discovered relay redirects are disabled")
	}}
}

// validateDiscoveryURL enforces the transport-level shape of a discovered
// relay. The database/network-level address guard is applied again in
// dialPublicAddress, after DNS resolution.
func validateDiscoveryURL(raw string) (string, error) {
	if raw == "" || strings.ContainsAny(raw, " \t\r\n") {
		return "", errors.New("discovered relay URL is empty or contains whitespace")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid discovered relay URL: %w", err)
	}
	if parsed.Scheme != "wss" {
		return "", fmt.Errorf("discovered relay %q is not wss", raw)
	}
	if parsed.Opaque != "" || parsed.Hostname() == "" || parsed.User != nil {
		return "", fmt.Errorf("discovered relay %q has no valid host or contains credentials", raw)
	}
	if parsed.Fragment != "" || strings.Contains(raw, "#") {
		return "", fmt.Errorf("discovered relay %q has a fragment", raw)
	}
	return parsed.String(), nil
}

func lookupPublicHost(ctx context.Context, host string) ([]net.IP, error) {
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(addresses))
	for _, address := range addresses {
		ips = append(ips, address.IP)
	}
	return ips, nil
}

// dialPublicAddress resolves inside DialContext and connects only to an
// address that passed the public-address guard. This prevents a DNS answer
// from changing between a separate pre-check and the real connection.
func dialPublicAddress(ctx context.Context, network, addr string, opts discoveryDialOptions) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host == "" || port == "" {
		return nil, fmt.Errorf("invalid discovered relay address %q", addr)
	}
	var ips []net.IP
	if literal := net.ParseIP(host); literal != nil {
		ips = []net.IP{literal}
	} else {
		ips, err = opts.resolve(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("resolve discovered relay %q: %w", host, err)
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("discovered relay %q resolved to no addresses", host)
	}
	for _, ip := range ips {
		if !isPublicRelayIP(ip) {
			return nil, fmt.Errorf("discovered relay %q resolved to non-public address %s", host, ip)
		}
	}
	var failures []error
	for _, ip := range ips {
		conn, err := opts.dial(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		failures = append(failures, err)
	}
	return nil, fmt.Errorf("connect discovered relay %q: %w", host, errors.Join(failures...))
}

// reservedRelayPrefixes contains ranges that net.IP accessors do not classify
// as private but which must never be reachable from event-provided metadata.
var reservedRelayPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // this network
	netip.MustParsePrefix("100.64.0.0/10"),   // carrier-grade NAT
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // documentation
	netip.MustParsePrefix("192.88.99.0/24"),  // deprecated 6to4 relay anycast
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // documentation
	netip.MustParsePrefix("203.0.113.0/24"),  // documentation
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved
	netip.MustParsePrefix("255.255.255.255/32"),
	netip.MustParsePrefix("100::/64"),       // discard-only
	netip.MustParsePrefix("2001::/32"),      // Teredo
	netip.MustParsePrefix("2001:2::/48"),    // benchmarking
	netip.MustParsePrefix("2001:10::/28"),   // ORCHID
	netip.MustParsePrefix("2001:20::/28"),   // ORCHIDv2
	netip.MustParsePrefix("2001:db8::/32"),  // documentation
	netip.MustParsePrefix("2002::/16"),      // 6to4
	netip.MustParsePrefix("3ffe::/16"),      // 6bone
	netip.MustParsePrefix("5f00::/8"),       // unallocated
	netip.MustParsePrefix("fe00::/9"),       // reserved
	netip.MustParsePrefix("fec0::/10"),      // deprecated site-local
	netip.MustParsePrefix("::/96"),          // deprecated IPv4-compatible
	netip.MustParsePrefix("3fff::/20"),      // documentation
	netip.MustParsePrefix("64:ff9b::/96"),   // NAT64 well-known prefix
	netip.MustParsePrefix("64:ff9b:1::/48"), // local-use NAT64
}

func isPublicRelayIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	if !addr.IsValid() || addr.IsUnspecified() || addr.IsLoopback() || addr.IsPrivate() ||
		addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsMulticast() {
		return false
	}
	for _, prefix := range reservedRelayPrefixes {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}
