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
