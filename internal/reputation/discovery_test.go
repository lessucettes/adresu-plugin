package reputation

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"fiatjaf.com/nostr"
	"github.com/coder/websocket"
	"github.com/lessucettes/adresu-plugin/internal/config"
	kitrep "github.com/lessucettes/adresu-plugin/pkg/adresu-kit/reputation"
)

type discoveryHandler func(context.Context, *websocket.Conn, string, nostr.Filter)

func serveDiscoveryRelay(t *testing.T, secure bool, handler discoveryHandler) *httptest.Server {
	t.Helper()
	serve := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		_, raw, err := conn.Read(ctx)
		if err != nil {
			return
		}
		var frame []json.RawMessage
		if json.Unmarshal(raw, &frame) != nil || len(frame) < 3 {
			t.Errorf("invalid discovery request: %s", raw)
			return
		}
		var command, subscription string
		var filter nostr.Filter
		if json.Unmarshal(frame[0], &command) != nil || command != "REQ" ||
			json.Unmarshal(frame[1], &subscription) != nil ||
			json.Unmarshal(frame[2], &filter) != nil {
			t.Errorf("invalid discovery request: %s", raw)
			return
		}
		handler(ctx, conn, subscription, filter)
	})
	var server *httptest.Server
	if secure {
		server = httptest.NewTLSServer(serve)
	} else {
		server = httptest.NewServer(serve)
	}
	t.Cleanup(server.Close)
	return server
}

func sendDiscoveryEvent(t *testing.T, ctx context.Context, conn *websocket.Conn, subscription string, event any) bool {
	t.Helper()
	raw, err := json.Marshal([]any{"EVENT", subscription, event})
	if err != nil || conn.Write(ctx, websocket.MessageText, raw) != nil {
		return false
	}
	return true
}

func sendDiscoveryEOSE(t *testing.T, ctx context.Context, conn *websocket.Conn, subscription string) bool {
	t.Helper()
	raw, err := json.Marshal([]any{"EOSE", subscription})
	if err != nil || conn.Write(ctx, websocket.MessageText, raw) != nil {
		return false
	}
	return true
}

func wsTestURL(server *httptest.Server) string {
	return "ws" + strings.TrimPrefix(server.URL, "http")
}

func secureTestURL(t *testing.T, server *httptest.Server, host string) string {
	t.Helper()
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return "wss://" + host + ":" + port
}

func discoveryDialOptionsFor(servers ...*httptest.Server) discoveryDialOptions {
	pool := x509.NewCertPool()
	targets := make(map[string]string, len(servers))
	for _, server := range servers {
		pool.AddCert(server.Certificate())
		_, port, _ := net.SplitHostPort(server.Listener.Addr().String())
		targets[port] = server.Listener.Addr().String()
	}
	return discoveryDialOptions{
		resolve: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("93.184.216.34")}, nil
		},
		dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			_, port, _ := net.SplitHostPort(addr)
			target, ok := targets[port]
			if !ok {
				return nil, fmt.Errorf("unexpected discovery dial %q", addr)
			}
			dialer := &net.Dialer{Timeout: time.Second}
			return dialer.DialContext(ctx, network, target)
		},
		tlsConfig: &tls.Config{RootCAs: pool},
	}
}

func signedMetadata(t *testing.T, key nostr.SecretKey, createdAt int64, tags nostr.Tags) nostr.Event {
	t.Helper()
	event := nostr.Event{Kind: nostr.KindRelayListMetadata, CreatedAt: nostr.Timestamp(createdAt), Tags: tags}
	if err := event.Sign(key); err != nil {
		t.Fatal(err)
	}
	return event
}

func discoveryConfig(seed nostr.PubKey, fixed, bootstrap string) config.ReputationConfig {
	cfg := testConfig(seed)
	cfg.Relays = []string{fixed}
	cfg.DiscoverRelays = true
	cfg.DiscoveryRelays = []string{bootstrap}
	cfg.FetchTimeout = 2 * time.Second
	cfg.MaxNodes = 1000
	return cfg
}

func TestDiscoverySourceTargetedOutboxFallback(t *testing.T) {
	aseed := nostr.KeyOne
	a := aseed.Public()
	bkey := nostr.Generate()
	b := bkey.Public()
	c := nostr.Generate().Public()
	fixedList := signedList(t, aseed, "fixed", nostr.Generate().Public())
	outboxList := signedList(t, bkey, "outbox", c)

	discovered := serveDiscoveryRelay(t, true, func(ctx context.Context, conn *websocket.Conn, sub string, filter nostr.Filter) {
		if len(filter.Authors) != 1 || filter.Authors[0] != b || !slices.Contains(filter.Kinds, nostr.KindFollowList) {
			t.Errorf("discovered query = %+v", filter)
			return
		}
		_ = sendDiscoveryEvent(t, ctx, conn, sub, outboxList)
		_ = sendDiscoveryEOSE(t, ctx, conn, sub)
	})
	outboxURL := secureTestURL(t, discovered, "relay.example.com")
	bootstrap := serveDiscoveryRelay(t, false, func(ctx context.Context, conn *websocket.Conn, sub string, filter nostr.Filter) {
		if len(filter.Authors) != 1 || filter.Authors[0] != b || !slices.Contains(filter.Kinds, nostr.KindRelayListMetadata) {
			t.Errorf("bootstrap query = %+v", filter)
			return
		}
		_ = sendDiscoveryEvent(t, ctx, conn, sub, signedMetadata(t, bkey, time.Now().Unix(),
			nostr.Tags{{"r", outboxURL, "write"}, {"r", "wss://read.example", "read"}}))
		_ = sendDiscoveryEOSE(t, ctx, conn, sub)
	})
	fixed := serveDiscoveryRelay(t, false, func(ctx context.Context, conn *websocket.Conn, sub string, filter nostr.Filter) {
		_ = sendDiscoveryEvent(t, ctx, conn, sub, fixedList)
		_ = sendDiscoveryEOSE(t, ctx, conn, sub)
	})

	source := newDiscoverySourceWithOptions(discoveryConfig(a, wsTestURL(fixed), wsTestURL(bootstrap)),
		discoveryDialOptionsFor(discovered))
	got, err := source.Fetch(context.Background(), []nostr.PubKey{a, b})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[a].EventID != fixedList.ID {
		t.Fatalf("fixed result was not preserved: %+v", got)
	}
	if list, ok := got[b]; !ok || list.EventID != outboxList.ID || len(list.Follows) != 1 || list.Follows[0] != c {
		t.Fatalf("discovered follow list = %+v", got[b])
	}
}

func TestDiscoverySourceRejectsUntrustedMetadata(t *testing.T) {
	aseed := nostr.KeyOne
	a := aseed.Public()
	bkey := nostr.Generate()
	b := bkey.Public()
	otherKey := nostr.Generate()
	c := nostr.Generate().Public()

	var oldHits, badHits atomic.Int32
	oldRelay := serveDiscoveryRelay(t, true, func(ctx context.Context, conn *websocket.Conn, sub string, filter nostr.Filter) {
		oldHits.Add(1)
		_ = sendDiscoveryEOSE(t, ctx, conn, sub)
	})
	badRelay := serveDiscoveryRelay(t, true, func(ctx context.Context, conn *websocket.Conn, sub string, filter nostr.Filter) {
		badHits.Add(1)
		_ = sendDiscoveryEOSE(t, ctx, conn, sub)
	})
	goodRelay := serveDiscoveryRelay(t, true, func(ctx context.Context, conn *websocket.Conn, sub string, filter nostr.Filter) {
		_ = sendDiscoveryEvent(t, ctx, conn, sub, signedList(t, bkey, "good", c))
		_ = sendDiscoveryEOSE(t, ctx, conn, sub)
	})
	goodURL := secureTestURL(t, goodRelay, "relay.example.com")
	oldURL := secureTestURL(t, oldRelay, "relay-old.example.com")
	badURL := secureTestURL(t, badRelay, "relay-bad.example.com")

	now := time.Now().Unix()
	valid := signedMetadata(t, bkey, now, nostr.Tags{{"r", goodURL, "write"}})
	old := signedMetadata(t, bkey, now-3600, nostr.Tags{{"r", oldURL, "write"}})
	badSignature := signedMetadata(t, bkey, now, nostr.Tags{{"r", badURL, "write"}})
	badSignature.Sig[0] ^= 1
	future := signedMetadata(t, bkey, now+3600, nostr.Tags{{"r", badURL, "write"}})
	wrongAuthor := signedMetadata(t, otherKey, now+10, nostr.Tags{{"r", badURL, "write"}})

	bootstrap := serveDiscoveryRelay(t, false, func(ctx context.Context, conn *websocket.Conn, sub string, filter nostr.Filter) {
		for _, event := range []nostr.Event{old, badSignature, wrongAuthor, future, valid} {
			if !sendDiscoveryEvent(t, ctx, conn, sub, event) {
				return
			}
		}
		_ = sendDiscoveryEvent(t, ctx, conn, sub, "malformed")
		_ = sendDiscoveryEOSE(t, ctx, conn, sub)
	})
	fixed := serveDiscoveryRelay(t, false, func(ctx context.Context, conn *websocket.Conn, sub string, filter nostr.Filter) {
		_ = sendDiscoveryEOSE(t, ctx, conn, sub)
	})
	source := newDiscoverySourceWithOptions(discoveryConfig(a, wsTestURL(fixed), wsTestURL(bootstrap)),
		discoveryDialOptionsFor(goodRelay, oldRelay, badRelay))
	got, err := source.Fetch(context.Background(), []nostr.PubKey{b})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(got[b].Follows) != 1 || got[b].Follows[0] != c {
		t.Fatalf("untrusted metadata influenced discovery: %+v", got)
	}
	if oldHits.Load() != 0 || badHits.Load() != 0 {
		t.Fatalf("old/unverified metadata was followed: old=%d bad=%d", oldHits.Load(), badHits.Load())
	}
}

func TestDiscoverySourceEmptyListAndMetadataCache(t *testing.T) {
	aseed := nostr.KeyOne
	a := aseed.Public()
	bkey := nostr.Generate()
	b := bkey.Public()
	var bootstrapHits atomic.Int32
	var outboxHits atomic.Int32
	discovered := serveDiscoveryRelay(t, true, func(ctx context.Context, conn *websocket.Conn, sub string, filter nostr.Filter) {
		outboxHits.Add(1)
		_ = sendDiscoveryEvent(t, ctx, conn, sub, signedList(t, bkey, ""))
		_ = sendDiscoveryEOSE(t, ctx, conn, sub)
	})
	outboxURL := secureTestURL(t, discovered, "relay.example.com")
	bootstrap := serveDiscoveryRelay(t, false, func(ctx context.Context, conn *websocket.Conn, sub string, filter nostr.Filter) {
		bootstrapHits.Add(1)
		_ = sendDiscoveryEvent(t, ctx, conn, sub, signedMetadata(t, bkey, time.Now().Unix(), nostr.Tags{{"r", outboxURL}}))
		_ = sendDiscoveryEOSE(t, ctx, conn, sub)
	})
	fixed := serveDiscoveryRelay(t, false, func(ctx context.Context, conn *websocket.Conn, sub string, filter nostr.Filter) {
		_ = sendDiscoveryEOSE(t, ctx, conn, sub)
	})
	source := newDiscoverySourceWithOptions(discoveryConfig(a, wsTestURL(fixed), wsTestURL(bootstrap)),
		discoveryDialOptionsFor(discovered))
	for i := 0; i < 2; i++ {
		got, err := source.Fetch(context.Background(), []nostr.PubKey{b})
		if err != nil {
			t.Fatal(err)
		}
		list, ok := got[b]
		if !ok || len(list.Follows) != 0 {
			t.Fatalf("verified empty list missing on fetch %d: %+v", i, got)
		}
	}
	if bootstrapHits.Load() != 1 || outboxHits.Load() != 2 {
		t.Fatalf("metadata cache was not reused: bootstrap=%d outbox=%d", bootstrapHits.Load(), outboxHits.Load())
	}
}

func TestDiscoverySourceKeepsCachedMetadataOnBootstrapFailure(t *testing.T) {
	aseed := nostr.KeyOne
	a := aseed.Public()
	bkey := nostr.Generate()
	b := bkey.Public()
	c := nostr.Generate().Public()
	var fail atomic.Bool
	discovered := serveDiscoveryRelay(t, true, func(ctx context.Context, conn *websocket.Conn, sub string, filter nostr.Filter) {
		_ = sendDiscoveryEvent(t, ctx, conn, sub, signedList(t, bkey, "cached", c))
		_ = sendDiscoveryEOSE(t, ctx, conn, sub)
	})
	outboxURL := secureTestURL(t, discovered, "relay.example.com")
	bootstrap := serveDiscoveryRelay(t, false, func(ctx context.Context, conn *websocket.Conn, sub string, filter nostr.Filter) {
		if fail.Load() {
			return
		}
		_ = sendDiscoveryEvent(t, ctx, conn, sub, signedMetadata(t, bkey, time.Now().Unix(), nostr.Tags{{"r", outboxURL}}))
		_ = sendDiscoveryEOSE(t, ctx, conn, sub)
	})
	fixed := serveDiscoveryRelay(t, false, func(ctx context.Context, conn *websocket.Conn, sub string, filter nostr.Filter) {
		_ = sendDiscoveryEOSE(t, ctx, conn, sub)
	})
	source := newDiscoverySourceWithOptions(discoveryConfig(a, wsTestURL(fixed), wsTestURL(bootstrap)),
		discoveryDialOptionsFor(discovered))
	if _, err := source.Fetch(context.Background(), []nostr.PubKey{b}); err != nil {
		t.Fatal(err)
	}
	fail.Store(true)
	source.cache.mu.Lock()
	source.cache.entries[b].checkedAt = time.Now().Add(-2 * discoveryMetadataTTL)
	source.cache.mu.Unlock()
	got, err := source.Fetch(context.Background(), []nostr.PubKey{b})
	if err != nil {
		t.Fatal(err)
	}
	if list, ok := got[b]; !ok || len(list.Follows) != 1 || list.Follows[0] != c {
		t.Fatalf("stale verified metadata was not reused: %+v", got)
	}
}

func TestDiscoverySourceCancellation(t *testing.T) {
	cfg := discoveryConfig(nostr.KeyOne.Public(), "ws://127.0.0.1:1", "ws://127.0.0.1:1")
	source := newDiscoverySourceWithOptions(cfg, discoveryDialOptions{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := source.Fetch(ctx, []nostr.PubKey{nostr.KeyOne.Public()}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled fetch error = %v", err)
	}
}

func TestDiscoveryGroupAggregateByteBudget(t *testing.T) {
	seed := nostr.KeyOne.Public()
	// Deliberately unsigned: the budget must apply before signature parsing.
	event := map[string]any{"pubkey": seed.Hex(), "kind": 3, "content": strings.Repeat("x", (1<<20)-512)}
	relay := serveDiscoveryRelay(t, false, func(ctx context.Context, conn *websocket.Conn, sub string, _ nostr.Filter) {
		for i := 0; i < 6; i++ {
			if !sendDiscoveryEvent(t, ctx, conn, sub, event) {
				return
			}
		}
		_ = sendDiscoveryEOSE(t, ctx, conn, sub)
	})
	cfg := discoveryConfig(seed, wsTestURL(relay), wsTestURL(relay))
	cfg.FetchTimeout = 10 * time.Second
	source := newDiscoverySourceWithOptions(cfg, discoveryDialOptions{})
	groups := make([]groupedQuery, 9)
	for i := range groups {
		groups[i] = groupedQuery{url: wsTestURL(relay), authors: []nostr.PubKey{seed}}
	}
	results, _ := source.runGroups(context.Background(), groups, nostr.KindFollowList, newOperatorClient())
	retained := 0
	limited := false
	for _, result := range results {
		for _, raw := range result.raws {
			retained += len(raw)
		}
		if result.err != nil && strings.Contains(result.err.Error(), "aggregate byte budget") {
			limited = true
		}
	}
	if retained > maxRelayBatchBytes || !limited {
		t.Fatalf("aggregate budget not enforced: retained=%d, limited=%v", retained, limited)
	}
}

func TestCompletedMetadataMissKeepsLastVerifiedOutbox(t *testing.T) {
	key := nostr.Generate()
	pk := key.Public()
	event := signedList(t, key, "cached outbox")
	outbox := serveDiscoveryRelay(t, true, func(ctx context.Context, conn *websocket.Conn, sub string, _ nostr.Filter) {
		_ = sendDiscoveryEvent(t, ctx, conn, sub, event)
		_ = sendDiscoveryEOSE(t, ctx, conn, sub)
	})
	empty := serveDiscoveryRelay(t, false, func(ctx context.Context, conn *websocket.Conn, sub string, _ nostr.Filter) {
		_ = sendDiscoveryEOSE(t, ctx, conn, sub)
	})
	cfg := discoveryConfig(pk, wsTestURL(empty), wsTestURL(empty))
	source := newDiscoverySourceWithOptions(cfg, discoveryDialOptionsFor(outbox))
	source.cache.putMetadata(pk, kitrep.RelayList{Author: pk, CreatedAt: 1, EventID: nostr.ID{1}, WriteRelays: []string{secureTestURL(t, outbox, "relay.example.com")}}, time.Now().Add(-2*discoveryMetadataTTL))
	for i := 0; i < 2; i++ {
		got, err := source.Fetch(context.Background(), []nostr.PubKey{pk})
		if err != nil || got[pk].EventID != event.ID {
			t.Fatalf("completed miss erased verified metadata on attempt %d: %+v, %v", i, got, err)
		}
	}
}

func TestSelectDiscoveryEndpointsCapsURLs(t *testing.T) {
	metadata := make(map[nostr.PubKey]kitrep.RelayList)
	for i := 0; i < 100; i++ {
		pk := nostr.Generate().Public()
		urls := make([]string, 0, 4)
		for j := 0; j < 4; j++ {
			urls = append(urls, fmt.Sprintf("wss://relay-%d-%d.example", i, j))
		}
		metadata[pk] = kitrep.RelayList{Author: pk, WriteRelays: urls}
	}
	groups := selectDiscoveryEndpoints(metadata)
	if len(groups) != maxDiscoveryEndpoints {
		t.Fatalf("selected %d endpoints, want %d", len(groups), maxDiscoveryEndpoints)
	}
	perAuthor := make(map[nostr.PubKey]int)
	for _, group := range groups {
		for _, pk := range group.authors {
			perAuthor[pk]++
		}
	}
	for pk, n := range perAuthor {
		if n > maxDiscoveryAuthorURLs {
			t.Fatalf("author %s selected %d relays", pk.Hex(), n)
		}
	}
}

func TestDiscoverySourceGroupsAuthorsAndBoundsConcurrency(t *testing.T) {
	const authors = 10
	keys := make([]nostr.SecretKey, authors)
	pubkeys := make([]nostr.PubKey, authors)
	relays := make([]*httptest.Server, authors)
	urls := make([]string, authors)
	var active, peak atomic.Int32
	for i := 0; i < authors; i++ {
		keys[i] = nostr.Generate()
		pubkeys[i] = keys[i].Public()
		relays[i] = serveDiscoveryRelay(t, true, func(ctx context.Context, conn *websocket.Conn, sub string, filter nostr.Filter) {
			current := active.Add(1)
			defer active.Add(-1)
			for {
				old := peak.Load()
				if current <= old || peak.CompareAndSwap(old, current) {
					break
				}
			}
			time.Sleep(75 * time.Millisecond)
			for _, pk := range filter.Authors {
				for j := range pubkeys {
					if pubkeys[j] == pk {
						_ = sendDiscoveryEvent(t, ctx, conn, sub, signedList(t, keys[j], "fanout"))
					}
				}
			}
			_ = sendDiscoveryEOSE(t, ctx, conn, sub)
		})
		urls[i] = secureTestURL(t, relays[i], fmt.Sprintf("relay-%d.example.com", i))
	}
	bootstrap := serveDiscoveryRelay(t, false, func(ctx context.Context, conn *websocket.Conn, sub string, filter nostr.Filter) {
		for i := range pubkeys {
			_ = sendDiscoveryEvent(t, ctx, conn, sub, signedMetadata(t, keys[i], time.Now().Unix(), nostr.Tags{{"r", urls[i]}}))
		}
		_ = sendDiscoveryEOSE(t, ctx, conn, sub)
	})
	fixed := serveDiscoveryRelay(t, false, func(ctx context.Context, conn *websocket.Conn, sub string, filter nostr.Filter) {
		_ = sendDiscoveryEOSE(t, ctx, conn, sub)
	})
	cfg := discoveryConfig(pubkeys[0], wsTestURL(fixed), wsTestURL(bootstrap))
	source := newDiscoverySourceWithOptions(cfg, discoveryDialOptionsFor(relays...))
	got, err := source.Fetch(context.Background(), pubkeys)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != authors {
		t.Fatalf("fetched %d/%d authors", len(got), authors)
	}
	if peak.Load() > maxDiscoveryConcurrency {
		t.Fatalf("discovery ran %d network requests concurrently", peak.Load())
	}
}

func TestDiscoverySourceGroupsAuthorsByRelay(t *testing.T) {
	const count = 3
	keys := make([]nostr.SecretKey, count)
	pubkeys := make([]nostr.PubKey, count)
	for i := range keys {
		keys[i] = nostr.Generate()
		pubkeys[i] = keys[i].Public()
	}
	var connections atomic.Int32
	relay := serveDiscoveryRelay(t, true, func(ctx context.Context, conn *websocket.Conn, sub string, filter nostr.Filter) {
		connections.Add(1)
		if len(filter.Authors) != count {
			t.Errorf("grouped query authors = %v", filter.Authors)
			return
		}
		for _, pk := range filter.Authors {
			for i := range pubkeys {
				if pubkeys[i] == pk {
					_ = sendDiscoveryEvent(t, ctx, conn, sub, signedList(t, keys[i], "grouped"))
				}
			}
		}
		_ = sendDiscoveryEOSE(t, ctx, conn, sub)
	})
	url := secureTestURL(t, relay, "relay.example.com")
	bootstrap := serveDiscoveryRelay(t, false, func(ctx context.Context, conn *websocket.Conn, sub string, filter nostr.Filter) {
		for i := range pubkeys {
			_ = sendDiscoveryEvent(t, ctx, conn, sub, signedMetadata(t, keys[i], time.Now().Unix(), nostr.Tags{{"r", url}}))
		}
		_ = sendDiscoveryEOSE(t, ctx, conn, sub)
	})
	fixed := serveDiscoveryRelay(t, false, func(ctx context.Context, conn *websocket.Conn, sub string, filter nostr.Filter) {
		_ = sendDiscoveryEOSE(t, ctx, conn, sub)
	})
	source := newDiscoverySourceWithOptions(discoveryConfig(pubkeys[0], wsTestURL(fixed), wsTestURL(bootstrap)),
		discoveryDialOptionsFor(relay))
	got, err := source.Fetch(context.Background(), pubkeys)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != count || connections.Load() != 1 {
		t.Fatalf("grouped query = %d lists over %d connections", len(got), connections.Load())
	}
}

func TestDiscoverySourceMissingMetadataIsNotAnEmptyList(t *testing.T) {
	b := nostr.Generate().Public()
	var bootstrapHits atomic.Int32
	bootstrap := serveDiscoveryRelay(t, false, func(ctx context.Context, conn *websocket.Conn, sub string, filter nostr.Filter) {
		bootstrapHits.Add(1)
		_ = sendDiscoveryEOSE(t, ctx, conn, sub)
	})
	fixed := serveDiscoveryRelay(t, false, func(ctx context.Context, conn *websocket.Conn, sub string, filter nostr.Filter) {
		_ = sendDiscoveryEOSE(t, ctx, conn, sub)
	})
	source := newDiscoverySourceWithOptions(discoveryConfig(nostr.KeyOne.Public(), wsTestURL(fixed), wsTestURL(bootstrap)),
		discoveryDialOptions{})
	for i := 0; i < 2; i++ {
		got, err := source.Fetch(context.Background(), []nostr.PubKey{b})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 0 {
			t.Fatalf("missing metadata manufactured a follow list: %+v", got)
		}
	}
	if bootstrapHits.Load() != 1 {
		t.Fatalf("negative metadata lookup was retried immediately: %d", bootstrapHits.Load())
	}
}

func TestDiscoveryCacheBoundedAndNewestMetadataWins(t *testing.T) {
	cache := newDiscoveryCache(2)
	now := time.Now()
	a, b := nostr.Generate().Public(), nostr.Generate().Public()
	cache.putMetadata(a, kitrep.RelayList{CreatedAt: 10, EventID: nostr.ID{2}, WriteRelays: []string{"wss://old.example"}}, now)
	cache.putMetadata(a, kitrep.RelayList{CreatedAt: 11, EventID: nostr.ID{2}, WriteRelays: []string{"wss://new.example"}}, now)
	cache.putMetadata(a, kitrep.RelayList{CreatedAt: 9, EventID: nostr.ID{1}, WriteRelays: []string{"wss://older-id.example"}}, now)
	if list, ok := cache.cached(a, now); !ok || list.WriteRelays[0] != "wss://new.example" {
		t.Fatalf("newest metadata was not retained: %+v", list)
	}
	// Equal timestamps select the lower event ID, regardless of arrival order.
	for _, id := range []byte{1, 3} {
		cache.putMetadata(a, kitrep.RelayList{CreatedAt: 11, EventID: nostr.ID{id}, WriteRelays: []string{"wss://tie.example"}}, now)
		if list, ok := cache.cached(a, now); !ok || list.EventID != (nostr.ID{1}) || list.WriteRelays[0] != "wss://tie.example" {
			t.Fatalf("equal-time metadata did not retain the lower event ID after %d: %+v", id, list)
		}
	}
	if _, ok := cache.cached(a, now.Add(discoveryMetadataTTL+time.Second)); ok {
		t.Fatal("stale metadata was reported fresh")
	}
	if _, ok := cache.stale(a); !ok {
		t.Fatal("stale metadata was discarded")
	}
	cache.markMissing(b, now)
	if !cache.backoff(b, now.Add(discoveryRetryDelay-time.Second)) {
		t.Fatal("negative lookup was not cached")
	}
	if cache.backoff(b, now.Add(discoveryRetryDelay+time.Second)) {
		t.Fatal("negative lookup cache did not expire")
	}
	cache.putMetadata(nostr.Generate().Public(), kitrep.RelayList{CreatedAt: 1, EventID: nostr.ID{1}}, now)
	if cache.len() != 2 {
		t.Fatalf("cache size = %d, want bounded 2", cache.len())
	}
}
