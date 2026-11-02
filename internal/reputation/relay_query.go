package reputation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"fiatjaf.com/nostr"
	"github.com/coder/websocket"
)

const (
	maxRelayBatchBytes = 32 << 20
	maxRelayFrameBytes = 2 << 20
)

var errAggregateRelayBudget = errors.New("relay group exceeded the aggregate byte budget")

// relayByteBudget bounds retained frames across every endpoint in a group,
// not merely each connection. A failed query never returns partial frames.
type relayByteBudget struct{ remaining atomic.Int64 }

func newRelayByteBudget() *relayByteBudget {
	budget := &relayByteBudget{}
	budget.remaining.Store(maxRelayBatchBytes)
	return budget
}

func (b *relayByteBudget) consume(n int) bool {
	return b == nil || b.remaining.Add(-int64(n)) >= 0
}

func (b *relayByteBudget) exhausted() bool {
	return b != nil && b.remaining.Load() <= 0
}

func newOperatorClient() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("reputation relay redirects are disabled")
	}}
}

func relaySubscription(kind nostr.Kind) string {
	if kind == nostr.KindRelayListMetadata {
		return "reputation-meta"
	}
	return "reputation"
}

func writeRelayQuery(ctx context.Context, conn *websocket.Conn, subscription string, authors []nostr.PubKey, kind nostr.Kind) error {
	request, err := json.Marshal([]any{"REQ", subscription, nostr.Filter{
		Kinds: []nostr.Kind{kind}, Authors: authors,
	}})
	if err != nil {
		return err
	}
	return conn.Write(ctx, websocket.MessageText, request)
}

// queryRelay returns raw signed events only after the relay completed the
// subscription with EOSE. It owns the whole NIP-42 connection state machine:
// pre-auth generations are discarded, only a matching positive AUTH ACK
// unlocks a fresh subscription, and frame, byte, auth-attempt and read-budget
// limits are enforced on every call.
func queryRelay(ctx context.Context, url string, authors []nostr.PubKey, kind nostr.Kind, client *http.Client, budget *relayByteBudget) ([]json.RawMessage, error) {
	if client == nil {
		client = newOperatorClient()
	}
	conn, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{HTTPClient: client})
	if err != nil {
		return nil, err
	}
	defer conn.CloseNow()
	conn.SetReadLimit(maxRelayFrameBytes)
	requested := make(map[nostr.PubKey]struct{}, len(authors))
	for _, pk := range authors {
		requested[pk] = struct{}{}
	}
	auth := newRelayAuth()
	base := relaySubscription(kind)
	subscription := base
	generation := 0
	if err := writeRelayQuery(ctx, conn, subscription, authors, kind); err != nil {
		return nil, err
	}
	var events []json.RawMessage
	totalBytes := 0
	// Each authentication attempt adds a challenge, an OK and a retried query,
	// so the frame budget grows by a fixed amount rather than without bound.
	readBudget := len(authors)*8 + 32 + maxAuthChallenges*4
	for received := 0; received < readBudget; received++ {
		_, raw, err := conn.Read(ctx)
		if err != nil {
			return nil, err
		}
		totalBytes += len(raw)
		if !budget.consume(len(raw)) {
			return nil, errAggregateRelayBudget
		}
		if totalBytes > maxRelayBatchBytes {
			return nil, errors.New("relay exceeded the follow-list byte budget")
		}
		var frame []json.RawMessage
		if err := json.Unmarshal(raw, &frame); err != nil || len(frame) < 2 {
			continue
		}
		var command string
		if json.Unmarshal(frame[0], &command) != nil {
			continue
		}
		switch command {
		case "AUTH":
			send, err := auth.acceptChallenge(frame)
			if err != nil {
				return nil, err
			}
			if send {
				if err := auth.send(ctx, conn, url, time.Now()); err != nil {
					return nil, err
				}
			}
			continue
		case "OK":
			matched, accepted, err := auth.acceptOK(frame)
			if err != nil {
				return nil, err
			}
			if !matched {
				continue
			}
			if !accepted {
				return nil, errors.New("relay refused collector authentication")
			}
			// Data seen before this ACK belongs to the pre-auth generation.
			auth.confirm()
			events = nil
			// Release the old generation before allocating a new subscription;
			// otherwise a relay with one available slot can refuse the retry.
			closeFrame, err := json.Marshal([]any{"CLOSE", subscription})
			if err != nil {
				return nil, err
			}
			if err := conn.Write(ctx, websocket.MessageText, closeFrame); err != nil {
				return nil, err
			}
			generation++
			subscription = fmt.Sprintf("%s-%d", base, generation)
			if err := writeRelayQuery(ctx, conn, subscription, authors, kind); err != nil {
				return nil, err
			}
			continue
		}
		var reference string
		if json.Unmarshal(frame[1], &reference) != nil || reference != subscription {
			continue
		}
		switch command {
		case "EOSE":
			incomplete := false
			if len(frame) > 2 {
				// NIP-67 hints are an array of strings, not a boolean object.
				var hints []string
				if json.Unmarshal(frame[2], &hints) != nil {
					return nil, errors.New("relay returned invalid EOSE hints")
				}
				for _, hint := range hints {
					switch hint {
					case "more":
						return nil, errors.New("relay returned incomplete follow-list history")
					case "auth":
						incomplete = true
					}
				}
			}
			if incomplete {
				if auth.pending() {
					// The relay demanded auth and our AUTH is in flight; this
					// EOSE describes the pre-auth generation and is not final.
					continue
				}
				if !auth.authenticated && auth.challenge != "" {
					if err := auth.send(ctx, conn, url, time.Now()); err != nil {
						return nil, err
					}
					continue
				}
				return nil, errors.New("relay requires authentication to complete the follow-list query")
			}
			if auth.pending() {
				// Never let a pre-auth EOSE establish a completed query; the
				// post-auth subscription must produce its own EOSE.
				continue
			}
			return events, nil
		case "CLOSED":
			if len(frame) != 3 {
				return nil, errors.New("relay refused the follow-list query")
			}
			var reason string
			if json.Unmarshal(frame[2], &reason) != nil {
				return nil, errors.New("relay refused the follow-list query")
			}
			switch {
			case strings.HasPrefix(reason, "auth-required:"):
				if auth.authenticated {
					return nil, errors.New("relay still requires authentication after collector AUTH")
				}
				if auth.awaitingOK {
					continue
				}
				if auth.challenge == "" {
					auth.requireChallenge()
					continue
				}
				if err := auth.send(ctx, conn, url, time.Now()); err != nil {
					return nil, err
				}
			case strings.HasPrefix(reason, "restricted:"):
				return nil, errors.New("relay restricted collector access to the follow-list query")
			default:
				return nil, errors.New("relay refused the follow-list query")
			}
		case "EVENT":
			if len(frame) != 3 || auth.pending() {
				continue
			}
			// Cheap header check before signature or tag decoding.
			var header struct {
				PubKey string `json:"pubkey"`
				Kind   uint16 `json:"kind"`
			}
			if json.Unmarshal(frame[2], &header) != nil || header.Kind != uint16(kind) {
				continue
			}
			pk, err := nostr.PubKeyFromHexCheap(header.PubKey)
			if _, ok := requested[pk]; err != nil || !ok {
				continue
			}
			events = append(events, bytes.Clone(frame[2]))
		}
	}
	return nil, errors.New("relay exceeded the follow-list response budget")
}
