package reputation

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"fiatjaf.com/nostr"
	"github.com/coder/websocket"
)

func relayServer(t *testing.T, events []nostr.Event, ending string) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if _, _, err := conn.Read(ctx); err != nil {
			return
		}
		for _, event := range events {
			raw, err := json.Marshal([]any{"EVENT", "reputation", event})
			if err != nil || conn.Write(ctx, websocket.MessageText, raw) != nil {
				return
			}
		}
		if ending != "" {
			if conn.Write(ctx, websocket.MessageText, []byte(ending)) != nil {
				return
			}
		}
		_, _, _ = conn.Read(ctx)
	}))
	t.Cleanup(server.Close)
	return "ws" + strings.TrimPrefix(server.URL, "http")
}

func signedList(t *testing.T, key nostr.SecretKey, content string, targets ...nostr.PubKey) nostr.Event {
	t.Helper()
	event := nostr.Event{Kind: 3, CreatedAt: nostr.Timestamp(time.Now().Unix()), Content: content}
	for _, target := range targets {
		event.Tags = append(event.Tags, nostr.Tag{"p", target.Hex()})
	}
	if err := event.Sign(key); err != nil {
		t.Fatal(err)
	}
	return event
}

func TestRelaySourceVerifiedReplacementAndTie(t *testing.T) {
	seed := nostr.KeyOne.Public()
	a, b := nostr.Generate().Public(), nostr.Generate().Public()
	first := signedList(t, nostr.KeyOne, "one", a)
	second := signedList(t, nostr.KeyOne, "two", b)
	second.CreatedAt = first.CreatedAt
	if err := second.Sign(nostr.KeyOne); err != nil {
		t.Fatal(err)
	}
	spoofed := second
	spoofed.ID[0] ^= 1
	unrequested := signedList(t, nostr.Generate(), "outside request")
	cfg := testConfig(seed)
	cfg.Relays = []string{relayServer(t, []nostr.Event{second, first, spoofed, unrequested}, `["EOSE","reputation"]`)}
	source := relaySource{cfg}
	got, err := source.Fetch(context.Background(), []nostr.PubKey{seed})
	if err != nil {
		t.Fatal(err)
	}
	want := first
	if newerListID(second, first) {
		want = second
	}
	if len(got) != 1 || got[seed].EventID != want.ID {
		t.Fatalf("wrong replacement selected: %+v", got)
	}
}

func TestRelaySourceHasATotalByteBudget(t *testing.T) {
	frame, err := json.Marshal([]any{"NOTICE", "reputation", strings.Repeat("x", 1<<20)})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		if _, _, err := conn.Read(ctx); err != nil {
			return
		}
		for i := 0; i < 40; i++ {
			if conn.Write(ctx, websocket.MessageText, frame) != nil {
				return
			}
		}
	}))
	defer server.Close()
	cfg := testConfig(nostr.KeyOne.Public())
	cfg.FetchTimeout = 5 * time.Second
	cfg.Relays = []string{"ws" + strings.TrimPrefix(server.URL, "http")}
	lists, err := (relaySource{cfg}).Fetch(context.Background(), []nostr.PubKey{nostr.KeyOne.Public()})
	if err == nil || !strings.Contains(err.Error(), "byte budget") || len(lists) != 0 {
		t.Fatalf("relay byte budget not enforced: lists=%v, err=%v", lists, err)
	}
}

func newerListID(a, b nostr.Event) bool { return a.ID.Hex() < b.ID.Hex() }

func TestRelaySourceIgnoresIncompleteSources(t *testing.T) {
	first := signedList(t, nostr.KeyOne, "completed", nostr.Generate().Public())
	newer := signedList(t, nostr.KeyOne, "incomplete")
	newer.CreatedAt = first.CreatedAt + 1
	if err := newer.Sign(nostr.KeyOne); err != nil {
		t.Fatal(err)
	}
	cfg := testConfig(nostr.KeyOne.Public())
	cfg.FetchTimeout = 100 * time.Millisecond
	cfg.Relays = []string{
		relayServer(t, []nostr.Event{first}, `["EOSE","reputation"]`),
		relayServer(t, []nostr.Event{newer}, ""),
	}
	lists, err := (relaySource{cfg}).Fetch(context.Background(), []nostr.PubKey{nostr.KeyOne.Public()})
	if err != nil || len(lists) != 1 || lists[first.PubKey].EventID != first.ID {
		t.Fatalf("incomplete source overrode completed query: %+v, %v", lists, err)
	}
}

func TestRelaySourceCompletionAndCancellation(t *testing.T) {
	for _, ending := range []string{`["EOSE","reputation"]`, `["EOSE","reputation",["finish"]]`, `["EOSE","reputation",["more"]]`, `["EOSE","reputation",["auth"]]`, `["EOSE","reputation",{"more":false}]`, `["CLOSED","reputation","blocked"]`, ""} {
		t.Run(ending, func(t *testing.T) {
			cfg := testConfig(nostr.KeyOne.Public())
			cfg.FetchTimeout = 100 * time.Millisecond
			cfg.Relays = []string{relayServer(t, nil, ending)}
			got, err := (relaySource{cfg}).Fetch(context.Background(), []nostr.PubKey{nostr.KeyOne.Public()})
			if len(got) != 0 {
				t.Fatal("empty response manufactured a follow list")
			}
			complete := ending == `["EOSE","reputation"]` || ending == `["EOSE","reputation",["finish"]]`
			if (err == nil) != complete {
				t.Fatalf("unexpected completion status: %v", err)
			}
		})
	}
}
