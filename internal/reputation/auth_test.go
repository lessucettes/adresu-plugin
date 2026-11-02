package reputation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"fiatjaf.com/nostr"
	"github.com/coder/websocket"
)

type relayFrame []json.RawMessage

func (f relayFrame) command() string {
	if len(f) == 0 {
		return ""
	}
	var command string
	_ = json.Unmarshal(f[0], &command)
	return command
}

func (f relayFrame) stringAt(index int) string {
	if index >= len(f) {
		return ""
	}
	var value string
	_ = json.Unmarshal(f[index], &value)
	return value
}

// authRelayServer runs a real WebSocket handler for one test connection. The
// handler receives the exact relay URL the client dialed, which must appear in
// the AUTH relay tag.
func authRelayServer(t *testing.T, handler func(context.Context, *websocket.Conn, string)) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		scheme := "ws"
		if r.TLS != nil {
			scheme = "wss"
		}
		handler(ctx, conn, scheme+"://"+r.Host)
	}))
	t.Cleanup(server.Close)
	return "ws" + strings.TrimPrefix(server.URL, "http")
}

func nextFrame(t *testing.T, ctx context.Context, conn *websocket.Conn) (relayFrame, bool) {
	t.Helper()
	_, raw, err := conn.Read(ctx)
	if err != nil {
		t.Errorf("read relay frame: %v", err)
		return nil, false
	}
	var frame relayFrame
	if err := json.Unmarshal(raw, &frame); err != nil || len(frame) < 2 {
		t.Errorf("invalid relay frame %q", raw)
		return nil, false
	}
	return frame, true
}

func sendFrame(t *testing.T, ctx context.Context, conn *websocket.Conn, value any) bool {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Errorf("encode relay frame: %v", err)
		return false
	}
	if err := conn.Write(ctx, websocket.MessageText, raw); err != nil {
		t.Errorf("write relay frame: %v", err)
		return false
	}
	return true
}

func expectQuery(t *testing.T, ctx context.Context, conn *websocket.Conn, forbidden string) (string, bool) {
	t.Helper()
	frame, ok := nextFrame(t, ctx, conn)
	if !ok {
		return "", false
	}
	if frame.command() != "CLOSE" || frame.stringAt(1) != forbidden {
		t.Errorf("expected CLOSE for retired subscription %q, got %s", forbidden, frame.command())
		return "", false
	}
	frame, ok = nextFrame(t, ctx, conn)
	if !ok {
		return "", false
	}
	if frame.command() != "REQ" {
		t.Errorf("expected REQ, got %s", frame.command())
		return "", false
	}
	subscription := frame.stringAt(1)
	if subscription == "" || subscription == forbidden {
		t.Errorf("REQ did not use a fresh subscription generation: %q", subscription)
		return "", false
	}
	return subscription, true
}

// expectCollectorAuth verifies every field NIP-42 requires from the client.
func expectCollectorAuth(t *testing.T, ctx context.Context, conn *websocket.Conn, relayURL, challenge string) (nostr.Event, bool) {
	t.Helper()
	frame, ok := nextFrame(t, ctx, conn)
	if !ok {
		return nostr.Event{}, false
	}
	if frame.command() != "AUTH" {
		t.Errorf("expected AUTH, got %s", frame.command())
		return nostr.Event{}, false
	}
	var event nostr.Event
	if err := json.Unmarshal(frame[1], &event); err != nil {
		t.Errorf("decode AUTH event: %v", err)
		return nostr.Event{}, false
	}
	if event.Kind != nostr.KindClientAuthentication {
		t.Errorf("AUTH event kind = %d", event.Kind)
	}
	if event.Content != "" {
		t.Errorf("AUTH event content = %q", event.Content)
	}
	wantTags := nostr.Tags{{"relay", relayURL}, {"challenge", challenge}}
	if !reflect.DeepEqual(event.Tags, wantTags) {
		t.Errorf("AUTH tags = %v, want %v", event.Tags, wantTags)
	}
	if !event.CheckID() || !event.VerifySignature() {
		t.Errorf("AUTH event id/signature is invalid")
	}
	if event.PubKey == nostr.KeyOne.Public() {
		t.Errorf("AUTH reused the operator key")
	}
	if age := time.Since(event.CreatedAt.Time()); age > time.Minute || age < -time.Minute {
		t.Errorf("AUTH timestamp is not current: %s ago", age)
	}
	return event, true
}

func TestRelaySourcePerformsNIP42HandshakeAndRetries(t *testing.T) {
	seed := nostr.KeyOne.Public()
	pre := signedList(t, nostr.KeyOne, "pre-auth", nostr.Generate().Public())
	target := nostr.Generate().Public()
	post := signedList(t, nostr.KeyOne, "post-auth", target)
	const challenge = "collector-challenge"
	relay := authRelayServer(t, func(ctx context.Context, conn *websocket.Conn, relayURL string) {
		frame, ok := nextFrame(t, ctx, conn)
		if !ok || frame.command() != "REQ" {
			t.Errorf("initial frame was not REQ")
			return
		}
		oldSubscription := frame.stringAt(1)
		if !sendFrame(t, ctx, conn, []any{"AUTH", challenge}) ||
			!sendFrame(t, ctx, conn, []any{"EVENT", oldSubscription, pre}) ||
			!sendFrame(t, ctx, conn, []any{"EOSE", oldSubscription}) {
			return
		}
		event, ok := expectCollectorAuth(t, ctx, conn, relayURL, challenge)
		if !ok {
			return
		}
		// The pre-auth EOSE above must not complete the query. Only the OK for
		// this exact AUTH event unlocks a fresh subscription.
		if !sendFrame(t, ctx, conn, []any{"OK", event.ID.Hex(), true, ""}) {
			return
		}
		// A stale EOSE from the old generation arriving after AUTH is ignored.
		if !sendFrame(t, ctx, conn, []any{"EOSE", oldSubscription}) {
			return
		}
		subscription, ok := expectQuery(t, ctx, conn, oldSubscription)
		if !ok {
			return
		}
		_ = sendFrame(t, ctx, conn, []any{"EVENT", subscription, post})
		_ = sendFrame(t, ctx, conn, []any{"EOSE", subscription})
	})
	cfg := testConfig(seed)
	cfg.FetchTimeout = 2 * time.Second
	cfg.Relays = []string{relay}
	got, err := (relaySource{cfg}).Fetch(context.Background(), []nostr.PubKey{seed})
	if err != nil {
		t.Fatal(err)
	}
	list, found := got[seed]
	if !found || len(got) != 1 || list.EventID != post.ID {
		t.Fatalf("pre-auth data leaked or post-auth query missing: %+v", got)
	}
	if len(list.Follows) != 1 || list.Follows[0] != target {
		t.Fatalf("post-auth list was not parsed: %+v", list)
	}
}

func TestRelaySourceRequiresMatchingPositiveACK(t *testing.T) {
	seed := nostr.KeyOne.Public()
	unrelated := signedList(t, nostr.Generate(), "unrelated")
	relay := authRelayServer(t, func(ctx context.Context, conn *websocket.Conn, relayURL string) {
		frame, ok := nextFrame(t, ctx, conn)
		if !ok || frame.command() != "REQ" {
			t.Errorf("initial frame was not REQ")
			return
		}
		subscription := frame.stringAt(1)
		if !sendFrame(t, ctx, conn, []any{"AUTH", "matching-only"}) {
			return
		}
		if _, ok := expectCollectorAuth(t, ctx, conn, relayURL, "matching-only"); !ok {
			return
		}
		if !sendFrame(t, ctx, conn, []any{"OK", unrelated.ID.Hex(), false, "unrelated"}) ||
			!sendFrame(t, ctx, conn, []any{"OK", unrelated.ID.Hex(), true, ""}) {
			return
		}
		// A complete-looking pre-auth response must not satisfy the query.
		if !sendFrame(t, ctx, conn, []any{"EOSE", subscription}) {
			return
		}
		readCtx, readCancel := context.WithTimeout(ctx, 50*time.Millisecond)
		_, raw, err := conn.Read(readCtx)
		readCancel()
		if err == nil {
			var retry relayFrame
			_ = json.Unmarshal(raw, &retry)
			t.Errorf("retried without a matching AUTH ACK: %s", retry.command())
		}
	})
	cfg := testConfig(seed)
	cfg.FetchTimeout = 150 * time.Millisecond
	cfg.Relays = []string{relay}
	got, err := (relaySource{cfg}).Fetch(context.Background(), []nostr.PubKey{seed})
	if err == nil || len(got) != 0 {
		t.Fatalf("unmatched ACK produced ready data: %+v, %v", got, err)
	}
}

func TestRelaySourceHandlesAuthRequiredClosed(t *testing.T) {
	seed := nostr.KeyOne.Public()
	for _, closedAfterChallenge := range []bool{false, true} {
		t.Run(fmt.Sprintf("closed_after_challenge_%t", closedAfterChallenge), func(t *testing.T) {
			post := signedList(t, nostr.KeyOne, "closed", nostr.Generate().Public())
			relay := authRelayServer(t, func(ctx context.Context, conn *websocket.Conn, relayURL string) {
				frame, ok := nextFrame(t, ctx, conn)
				if !ok || frame.command() != "REQ" {
					t.Errorf("initial frame was not REQ")
					return
				}
				oldSubscription := frame.stringAt(1)
				if closedAfterChallenge {
					if !sendFrame(t, ctx, conn, []any{"AUTH", "closed-after"}) {
						return
					}
					event, ok := expectCollectorAuth(t, ctx, conn, relayURL, "closed-after")
					if !ok {
						return
					}
					if !sendFrame(t, ctx, conn, []any{"CLOSED", oldSubscription, "auth-required: members only"}) {
						return
					}
					if !sendFrame(t, ctx, conn, []any{"OK", event.ID.Hex(), true, ""}) {
						return
					}
				} else {
					if !sendFrame(t, ctx, conn, []any{"CLOSED", oldSubscription, "auth-required: members only"}) ||
						!sendFrame(t, ctx, conn, []any{"AUTH", "closed-before"}) {
						return
					}
					event, ok := expectCollectorAuth(t, ctx, conn, relayURL, "closed-before")
					if !ok {
						return
					}
					if !sendFrame(t, ctx, conn, []any{"OK", event.ID.Hex(), true, ""}) {
						return
					}
				}
				subscription, ok := expectQuery(t, ctx, conn, oldSubscription)
				if !ok {
					return
				}
				_ = sendFrame(t, ctx, conn, []any{"EVENT", subscription, post})
				_ = sendFrame(t, ctx, conn, []any{"EOSE", subscription})
			})
			cfg := testConfig(seed)
			cfg.FetchTimeout = 2 * time.Second
			cfg.Relays = []string{relay}
			got, err := (relaySource{cfg}).Fetch(context.Background(), []nostr.PubKey{seed})
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 || got[seed].EventID != post.ID {
				t.Fatalf("auth-required flow did not complete: %+v", got)
			}
		})
	}
}

func TestRelaySourceHandlesAuthEOSEHint(t *testing.T) {
	seed := nostr.KeyOne.Public()
	post := signedList(t, nostr.KeyOne, "hinted", nostr.Generate().Public())
	relay := authRelayServer(t, func(ctx context.Context, conn *websocket.Conn, relayURL string) {
		frame, ok := nextFrame(t, ctx, conn)
		if !ok || frame.command() != "REQ" {
			t.Errorf("initial frame was not REQ")
			return
		}
		oldSubscription := frame.stringAt(1)
		if !sendFrame(t, ctx, conn, []any{"AUTH", "hinted"}) {
			return
		}
		event, ok := expectCollectorAuth(t, ctx, conn, relayURL, "hinted")
		if !ok {
			return
		}
		if !sendFrame(t, ctx, conn, []any{"EOSE", oldSubscription, []string{"auth"}}) {
			return
		}
		if !sendFrame(t, ctx, conn, []any{"OK", event.ID.Hex(), true, ""}) {
			return
		}
		subscription, ok := expectQuery(t, ctx, conn, oldSubscription)
		if !ok {
			return
		}
		_ = sendFrame(t, ctx, conn, []any{"EVENT", subscription, post})
		_ = sendFrame(t, ctx, conn, []any{"EOSE", subscription})
	})
	cfg := testConfig(seed)
	cfg.FetchTimeout = 2 * time.Second
	cfg.Relays = []string{relay}
	got, err := (relaySource{cfg}).Fetch(context.Background(), []nostr.PubKey{seed})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[seed].EventID != post.ID {
		t.Fatalf("auth EOSE hint was not retried: %+v", got)
	}
}

func TestRelaySourceRefusesRejectedAuthAndRestrictedAccess(t *testing.T) {
	seed := nostr.KeyOne.Public()
	t.Run("negative_auth_ack", func(t *testing.T) {
		relay := authRelayServer(t, func(ctx context.Context, conn *websocket.Conn, relayURL string) {
			if _, ok := nextFrame(t, ctx, conn); !ok {
				return
			}
			if !sendFrame(t, ctx, conn, []any{"AUTH", "rejected"}) {
				return
			}
			event, ok := expectCollectorAuth(t, ctx, conn, relayURL, "rejected")
			if !ok {
				return
			}
			_ = sendFrame(t, ctx, conn, []any{"OK", event.ID.Hex(), false, "restricted: not whitelisted"})
		})
		cfg := testConfig(seed)
		cfg.FetchTimeout = 2 * time.Second
		cfg.Relays = []string{relay}
		got, err := (relaySource{cfg}).Fetch(context.Background(), []nostr.PubKey{seed})
		if err == nil || !strings.Contains(err.Error(), "refused collector authentication") || len(got) != 0 {
			t.Fatalf("rejected auth produced data: %+v, %v", got, err)
		}
	})
	t.Run("restricted_closed_after_auth", func(t *testing.T) {
		relay := authRelayServer(t, func(ctx context.Context, conn *websocket.Conn, relayURL string) {
			frame, ok := nextFrame(t, ctx, conn)
			if !ok {
				return
			}
			oldSubscription := frame.stringAt(1)
			if !sendFrame(t, ctx, conn, []any{"AUTH", "restricted"}) {
				return
			}
			event, ok := expectCollectorAuth(t, ctx, conn, relayURL, "restricted")
			if !ok {
				return
			}
			if !sendFrame(t, ctx, conn, []any{"OK", event.ID.Hex(), true, ""}) {
				return
			}
			subscription, ok := expectQuery(t, ctx, conn, oldSubscription)
			if !ok {
				return
			}
			_ = sendFrame(t, ctx, conn, []any{"CLOSED", subscription, "restricted: not on allowlist"})
		})
		cfg := testConfig(seed)
		cfg.FetchTimeout = 2 * time.Second
		cfg.Relays = []string{relay}
		got, err := (relaySource{cfg}).Fetch(context.Background(), []nostr.PubKey{seed})
		if err == nil || !strings.Contains(err.Error(), "restricted") || len(got) != 0 {
			t.Fatalf("restricted relay produced data: %+v, %v", got, err)
		}
	})
}

func TestRelaySourceHandlesChangedChallenges(t *testing.T) {
	seed := nostr.KeyOne.Public()
	post := signedList(t, nostr.KeyOne, "changed", nostr.Generate().Public())
	relay := authRelayServer(t, func(ctx context.Context, conn *websocket.Conn, relayURL string) {
		frame, ok := nextFrame(t, ctx, conn)
		if !ok {
			return
		}
		oldSubscription := frame.stringAt(1)
		if !sendFrame(t, ctx, conn, []any{"AUTH", "first"}) {
			return
		}
		first, ok := expectCollectorAuth(t, ctx, conn, relayURL, "first")
		if !ok {
			return
		}
		// A replacement challenge invalidates the AUTH still in flight.
		if !sendFrame(t, ctx, conn, []any{"AUTH", "second"}) {
			return
		}
		second, ok := expectCollectorAuth(t, ctx, conn, relayURL, "second")
		if !ok {
			return
		}
		if first.ID == second.ID {
			t.Errorf("changed challenge reused the same AUTH event")
		}
		// The stale positive ACK for the first challenge must not retry REQ.
		if !sendFrame(t, ctx, conn, []any{"OK", first.ID.Hex(), true, ""}) {
			return
		}
		if !sendFrame(t, ctx, conn, []any{"OK", second.ID.Hex(), true, ""}) {
			return
		}
		subscription, ok := expectQuery(t, ctx, conn, oldSubscription)
		if !ok {
			return
		}
		_ = sendFrame(t, ctx, conn, []any{"EVENT", subscription, post})
		_ = sendFrame(t, ctx, conn, []any{"EOSE", subscription})
	})
	cfg := testConfig(seed)
	cfg.FetchTimeout = 2 * time.Second
	cfg.Relays = []string{relay}
	got, err := (relaySource{cfg}).Fetch(context.Background(), []nostr.PubKey{seed})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[seed].EventID != post.ID {
		t.Fatalf("changed challenge flow did not complete: %+v", got)
	}
}

func TestRelaySourceBoundsRepeatedChallenges(t *testing.T) {
	seed := nostr.KeyOne.Public()
	relay := authRelayServer(t, func(ctx context.Context, conn *websocket.Conn, relayURL string) {
		if _, ok := nextFrame(t, ctx, conn); !ok {
			return
		}
		for i := 0; i < maxAuthChallenges+1; i++ {
			challenge := fmt.Sprintf("challenge-%d", i)
			if !sendFrame(t, ctx, conn, []any{"AUTH", challenge}) {
				return
			}
			if i < maxAuthChallenges {
				if _, ok := expectCollectorAuth(t, ctx, conn, relayURL, challenge); !ok {
					return
				}
			}
		}
	})
	cfg := testConfig(seed)
	cfg.FetchTimeout = 2 * time.Second
	cfg.Relays = []string{relay}
	got, err := (relaySource{cfg}).Fetch(context.Background(), []nostr.PubKey{seed})
	if err == nil || !strings.Contains(err.Error(), "attempt budget") || len(got) != 0 {
		t.Fatalf("repeated challenges were not bounded: %+v, %v", got, err)
	}
}

func TestRelaySourceCancelsDuringAuthentication(t *testing.T) {
	seed := nostr.KeyOne.Public()
	authSent := make(chan struct{})
	relay := authRelayServer(t, func(ctx context.Context, conn *websocket.Conn, relayURL string) {
		if _, ok := nextFrame(t, ctx, conn); !ok {
			return
		}
		if !sendFrame(t, ctx, conn, []any{"AUTH", "cancelled"}) {
			return
		}
		if _, ok := expectCollectorAuth(t, ctx, conn, relayURL, "cancelled"); !ok {
			return
		}
		close(authSent)
		select {
		case <-ctx.Done():
		case <-time.After(300 * time.Millisecond):
		}
	})
	cfg := testConfig(seed)
	cfg.FetchTimeout = 5 * time.Second
	cfg.Relays = []string{relay}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-authSent
		cancel()
	}()
	got, err := (relaySource{cfg}).Fetch(ctx, []nostr.PubKey{seed})
	if err == nil || len(got) != 0 || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation during AUTH returned data: %+v, %v", got, err)
	}
}

func TestRelayAuthUsesFreshEphemeralCollectorKey(t *testing.T) {
	first, second := newRelayAuth(), newRelayAuth()
	if first.key.Public() == second.key.Public() {
		t.Fatal("connections reused the same collector key")
	}
	if first.key.Public() == nostr.KeyOne.Public() {
		t.Fatal("collector key equals the operator key")
	}
}
