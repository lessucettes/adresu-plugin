package reputation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"fiatjaf.com/nostr"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/coder/websocket"
	"github.com/lessucettes/adresu-plugin/pkg/adresu-kit/nip"
)

const (
	// maxAuthChallenges bounds relay-initiated authentication attempts on one
	// connection so a relay cannot make the collector sign forever.
	maxAuthChallenges = 3
	// maxAuthChallengeBytes bounds the challenge echoed into a signed event.
	maxAuthChallengeBytes = 512
)

// relayAuth is the per-connection NIP-42 client state. Its key is a fresh,
// anonymous collector identity generated for this connection only. It is an
// ephemeral identity, not an access credential: it is never loaded from
// configuration or from the operator, never persisted, and never logged. It
// only proves continuity of this single relay connection; paid or whitelisted
// access still depends on the relay.
type relayAuth struct {
	key           nostr.SecretKey
	challenge     string
	pendingID     nostr.ID
	awaitingOK    bool
	authenticated bool
	needed        bool
	attempts      int
}

func newRelayAuth() *relayAuth { return &relayAuth{key: nostr.Generate()} }

// pending reports whether the relay demanded authentication that has not
// completed yet. Events and EOSE received in this state belong to a pre-auth
// generation and cannot establish a completed query.
func (a *relayAuth) pending() bool { return a.needed || a.awaitingOK }

// acceptChallenge records a relay challenge and reports whether the caller
// should answer with AUTH. Repeated copies of the current challenge are
// ignored. A changed challenge invalidates any AUTH still awaiting an OK.
func (a *relayAuth) acceptChallenge(frame []json.RawMessage) (bool, error) {
	if len(frame) != 2 {
		return false, errors.New("relay sent an invalid AUTH challenge")
	}
	var challenge string
	if json.Unmarshal(frame[1], &challenge) != nil || challenge == "" || len(challenge) > maxAuthChallengeBytes {
		return false, errors.New("relay sent an invalid AUTH challenge")
	}
	if challenge == a.challenge {
		return false, nil
	}
	if a.attempts >= maxAuthChallenges {
		return false, errors.New("relay exceeded the collector authentication attempt budget")
	}
	a.challenge = challenge
	a.authenticated = false
	a.pendingID = nostr.ZeroID
	a.awaitingOK = false
	return true, nil
}

// acceptOK handles an OK addressed to the pending AUTH event. matched reports
// whether the id belongs to this collector's in-flight AUTH; accepted reports
// the relay's boolean verdict. Unrelated OK frames are not matched.
func (a *relayAuth) acceptOK(frame []json.RawMessage) (matched, accepted bool, err error) {
	if len(frame) != 4 || !a.awaitingOK {
		return false, false, nil
	}
	var idHex string
	if json.Unmarshal(frame[1], &idHex) != nil {
		return false, false, nil
	}
	id, err := nostr.IDFromHex(idHex)
	if err != nil || id != a.pendingID {
		return false, false, nil
	}
	if json.Unmarshal(frame[2], &accepted) != nil {
		return true, false, errors.New("relay returned an invalid AUTH response")
	}
	return true, accepted, nil
}

// send signs and writes exactly one client AUTH message. The event is kind
// 22242 with the current time, empty content, and exactly the relay URL and
// challenge tags required by NIP-42. It is never written as an EVENT.
func (a *relayAuth) send(ctx context.Context, conn *websocket.Conn, relayURL string, now time.Time) error {
	if a.challenge == "" {
		return errors.New("collector authentication has no relay challenge")
	}
	if a.authenticated {
		return errors.New("collector connection is already authenticated")
	}
	if a.awaitingOK {
		return errors.New("collector authentication is already awaiting a response")
	}
	if a.attempts >= maxAuthChallenges {
		return errors.New("relay exceeded the collector authentication attempt budget")
	}
	event := nostr.Event{
		CreatedAt: nostr.Timestamp(now.Unix()),
		Kind:      nostr.KindClientAuthentication,
		Tags:      nostr.Tags{{"relay", relayURL}, {"challenge", a.challenge}},
		Content:   "",
	}
	// The pinned nostr serializer mishandles some JSON control characters;
	// a relay's challenge is arbitrary text, so sign the kit's canonical ID.
	event.PubKey = a.key.Public()
	event.ID = nip.CanonicalEventID(ctx, &event)
	privateKey, _ := btcec.PrivKeyFromBytes(a.key[:])
	signature, err := schnorr.Sign(privateKey, event.ID[:])
	if err != nil {
		return fmt.Errorf("sign collector AUTH event: %w", err)
	}
	copy(event.Sig[:], signature.Serialize())
	raw, err := json.Marshal([]any{"AUTH", event})
	if err != nil {
		return fmt.Errorf("encode collector AUTH event: %w", err)
	}
	if err := conn.Write(ctx, websocket.MessageText, raw); err != nil {
		return err
	}
	a.pendingID = event.ID
	a.awaitingOK = true
	a.attempts++
	a.needed = false
	return nil
}

func (a *relayAuth) confirm() {
	a.authenticated = true
	a.awaitingOK = false
	a.pendingID = nostr.ZeroID
	a.needed = false
}

func (a *relayAuth) requireChallenge() { a.needed = true }
