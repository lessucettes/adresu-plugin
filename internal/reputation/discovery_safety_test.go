package reputation

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestValidateDiscoveryURL(t *testing.T) {
	valid := []string{"wss://relay.example.com", "wss://relay.example.com/path"}
	for _, raw := range valid {
		if got, err := validateDiscoveryURL(raw); err != nil || got == "" {
			t.Fatalf("valid URL %q rejected: %v", raw, err)
		}
	}
	invalid := []string{
		"", "ws://relay.example.com", "http://relay.example.com", "https://relay.example.com",
		"wss://user:pass@relay.example.com", "wss://relay.example.com/#section",
		"wss://relay.example.com/#", "wss:///path", " wss://relay.example.com",
	}
	for _, raw := range invalid {
		if _, err := validateDiscoveryURL(raw); err == nil {
			t.Fatalf("insecure URL %q accepted", raw)
		}
	}
}

func TestPublicRelayIPGuard(t *testing.T) {
	public := []string{"93.184.216.34", "8.8.8.8", "2606:4700:4700::1111", "2001:4860:4860::8888"}
	for _, text := range public {
		if !isPublicRelayIP(net.ParseIP(text)) {
			t.Fatalf("public address %s was blocked", text)
		}
	}
	blocked := []string{
		"127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.169.254",
		"0.0.0.0", "224.0.0.1", "100.64.0.1", "100.127.255.255", "192.0.0.1",
		"192.0.2.1", "198.18.0.1", "198.51.100.1", "203.0.113.1", "240.0.0.1",
		"255.255.255.255", "::1", "::", "fc00::1", "fd00::1", "fe80::1", "ff02::1",
		"2001:db8::1", "100::1", "2001:2::1", "2002::1", "64:ff9b::1",
		"3ffe::1", "fe00::1", "fec0::1", "::2", "3fff::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1",
	}
	for _, text := range blocked {
		if isPublicRelayIP(net.ParseIP(text)) {
			t.Fatalf("non-public address %s was allowed", text)
		}
	}
}

func TestDiscoveryDialUsesResolvedPublicAddress(t *testing.T) {
	var dialed string
	opts := discoveryDialOptions{
		resolve: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("93.184.216.34")}, nil
		},
		dial: func(_ context.Context, _ string, addr string) (net.Conn, error) {
			dialed = addr
			client, server := net.Pipe()
			_ = server.Close()
			return client, nil
		},
	}
	conn, err := dialPublicAddress(context.Background(), "tcp", "relay.example.com:443", opts)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if dialed != "93.184.216.34:443" {
		t.Fatalf("dialed %q, want the validated resolved address", dialed)
	}
}

func TestDiscoveryDialBlocksPrivateAndMappedAddresses(t *testing.T) {
	for _, address := range []string{"relay.example.com:443", "[::ffff:127.0.0.1]:443"} {
		called := false
		opts := discoveryDialOptions{
			resolve: func(context.Context, string) ([]net.IP, error) {
				return []net.IP{net.ParseIP("10.0.0.1")}, nil
			},
			dial: func(context.Context, string, string) (net.Conn, error) {
				called = true
				client, server := net.Pipe()
				_ = server.Close()
				return client, nil
			},
		}
		if _, err := dialPublicAddress(context.Background(), "tcp", address, opts); err == nil {
			t.Fatalf("non-public destination %q was dialed", address)
		}
		if called {
			t.Fatalf("dial hook ran for blocked destination %q", address)
		}
	}
}

func TestDiscoveryDialRechecksDNSOnEveryConnection(t *testing.T) {
	var answers atomic.Int32
	opts := discoveryDialOptions{
		resolve: func(context.Context, string) ([]net.IP, error) {
			if answers.Add(1) == 1 {
				return []net.IP{net.ParseIP("93.184.216.34")}, nil
			}
			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		},
		dial: func(context.Context, string, string) (net.Conn, error) {
			client, server := net.Pipe()
			_ = server.Close()
			return client, nil
		},
	}
	conn, err := dialPublicAddress(context.Background(), "tcp", "rebind.example.com:443", opts)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if _, err := dialPublicAddress(context.Background(), "tcp", "rebind.example.com:443", opts); err == nil {
		t.Fatal("DNS rebinding answer was not rejected by the second dial")
	}
}

func TestDiscoveryClientIgnoresProxyEnvironment(t *testing.T) {
	var proxyHits atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		proxyHits.Add(1)
	}))
	defer proxy.Close()
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("NO_PROXY", "")
	client := newDiscoveryClient(discoveryDialOptions{
		resolve: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("93.184.216.34")}, nil
		},
		dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, fmt.Errorf("blocked test dial")
		},
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://relay.example.com/", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Do(req); err == nil {
		t.Fatal("request unexpectedly succeeded")
	}
	if proxyHits.Load() != 0 {
		t.Fatalf("discovery client used the proxy environment: %d hits", proxyHits.Load())
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil {
		t.Fatal("discovery transport has a proxy function")
	}
}

func TestDiscoveryClientRejectsRedirects(t *testing.T) {
	var targetHits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		targetHits.Add(1)
	}))
	defer target.Close()
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer source.Close()
	_, port, err := net.SplitHostPort(source.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(source.Certificate())
	client := newDiscoveryClient(discoveryDialOptions{
		resolve: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("93.184.216.34")}, nil
		},
		dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, source.Listener.Addr().String())
		},
		tlsConfig: &tls.Config{RootCAs: pool},
	})
	url := "https://relay.example.com:" + port
	if _, err := client.Get(url); err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("redirect was not rejected: %v", err)
	}
	if targetHits.Load() != 0 {
		t.Fatalf("redirect target was contacted: %d", targetHits.Load())
	}
}
