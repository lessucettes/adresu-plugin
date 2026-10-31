package policy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"fiatjaf.com/nostr"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// testStore is an in-memory store.Store that can inject failures and block
// bans so async behavior can be observed.
type testStore struct {
	mu      sync.Mutex
	banned  map[string]bool
	applied map[string]bool

	honorContext bool
	isErr        error
	applyErr     error

	banCalls   int
	unbanCalls int

	banStarted     chan struct{}
	banStartedOnce sync.Once
	banBlock       <-chan struct{}
}

func newTestStore() *testStore {
	return &testStore{banned: make(map[string]bool), applied: make(map[string]bool)}
}

func (s *testStore) IsAuthorBanned(ctx context.Context, pubkey string) (bool, error) {
	if s.honorContext {
		if err := ctx.Err(); err != nil {
			return false, err
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.isErr != nil {
		return false, s.isErr
	}
	return s.banned[strings.ToLower(pubkey)], nil
}

func (s *testStore) BanAuthor(ctx context.Context, pubkey string, _ time.Duration) error {
	if s.banStarted != nil {
		s.banStartedOnce.Do(func() { close(s.banStarted) })
	}
	if s.banBlock != nil {
		select {
		case <-s.banBlock:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if s.honorContext {
		if err := ctx.Err(); err != nil {
			return err
		}
	}

	s.mu.Lock()
	s.banCalls++
	s.banned[strings.ToLower(pubkey)] = true
	s.mu.Unlock()
	return nil
}

func (s *testStore) UnbanAuthor(ctx context.Context, pubkey string) error {
	if s.honorContext {
		if err := ctx.Err(); err != nil {
			return err
		}
	}

	s.mu.Lock()
	s.unbanCalls++
	delete(s.banned, strings.ToLower(pubkey))
	s.mu.Unlock()
	return nil
}

func (s *testStore) ApplyModeration(ctx context.Context, actionID, pubkey string, banDuration time.Duration) (bool, error) {
	if s.honorContext {
		if err := ctx.Err(); err != nil {
			return false, err
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.applyErr != nil {
		return false, s.applyErr
	}
	if banDuration < 0 {
		return false, fmt.Errorf("negative ban duration: %s", banDuration)
	}
	if s.applied[actionID] {
		return false, nil
	}
	if banDuration == 0 {
		s.unbanCalls++
		delete(s.banned, strings.ToLower(pubkey))
	} else {
		s.banCalls++
		s.banned[strings.ToLower(pubkey)] = true
	}
	s.applied[actionID] = true
	return true, nil
}

func (s *testStore) Close() error { return nil }

func (s *testStore) isBanned(pubkey nostr.PubKey) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.banned[pubkey.Hex()]
}

func (s *testStore) banCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.banCalls
}

func (s *testStore) unbanCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.unbanCalls
}

// testStrfry records DeleteEventsByAuthor calls.
type testStrfry struct {
	mu    sync.Mutex
	calls []string
	err   error
}

func (c *testStrfry) DeleteEventsByAuthor(author string) error {
	c.mu.Lock()
	c.calls = append(c.calls, author)
	err := c.err
	c.mu.Unlock()
	return err
}

func (c *testStrfry) callCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.calls)
}

func (c *testStrfry) callAuthors() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.calls...)
}

func newKeyPair(t *testing.T) (sk nostr.SecretKey, pk nostr.PubKey) {
	t.Helper()

	sk = nostr.Generate()
	return sk, sk.Public()
}

func signedEvent(t *testing.T, sk nostr.SecretKey, kind nostr.Kind, content string, tags nostr.Tags) *nostr.Event {
	t.Helper()

	event := &nostr.Event{
		Kind:      kind,
		CreatedAt: nostr.Now(),
		Content:   content,
		Tags:      tags,
	}
	if err := event.Sign(sk); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	return event
}

// signedEventWithWirePubKey signs the NIP-01 body using pubKeyHex exactly as
// it appeared on the wire. The typed Event stores the same public key bytes,
// but its canonical serializer would lowercase them, so tests that exercise
// strfry's verbatim pubkey hashing must build the signed bytes explicitly and
// attach pubKeyHex with nip.WithWirePubKey.
func signedEventWithWirePubKey(t *testing.T, sk nostr.SecretKey, pubKeyHex string, kind nostr.Kind, content string, tags nostr.Tags) *nostr.Event {
	t.Helper()

	createdAt := nostr.Now()
	if tags == nil {
		tags = nostr.Tags{}
	}
	tagsJSON, err := json.Marshal(tags)
	if err != nil {
		t.Fatalf("marshal tags: %v", err)
	}
	contentJSON, err := json.Marshal(content)
	if err != nil {
		t.Fatalf("marshal content: %v", err)
	}
	serialized := fmt.Sprintf(`[0,"%s",%d,%d,%s,%s]`,
		pubKeyHex, int64(createdAt), int(kind), tagsJSON, contentJSON)
	hash := sha256.Sum256([]byte(serialized))

	keyBytes := sk[:]
	privateKey, _ := btcec.PrivKeyFromBytes(keyBytes)
	sig, err := schnorr.Sign(privateKey, hash[:])
	if err != nil {
		t.Fatalf("sign event: %v", err)
	}

	return &nostr.Event{
		ID:        nostr.ID(hash),
		PubKey:    sk.Public(),
		CreatedAt: createdAt,
		Kind:      kind,
		Tags:      tags,
		Content:   content,
		Sig:       [64]byte(sig.Serialize()),
	}
}

func waitFor(t *testing.T, timeout time.Duration, condition func() bool, message string) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal(message)
}

func signDelegationToken(t *testing.T, delegatorSK nostr.SecretKey, delegateePubKey nostr.PubKey, conditions string) string {
	t.Helper()

	keyBytes := delegatorSK[:]
	privateKey, _ := btcec.PrivKeyFromBytes(keyBytes)

	token := fmt.Sprintf("nostr:delegation:%s:%s", delegateePubKey.Hex(), conditions)
	hash := sha256.Sum256([]byte(token))
	sig, err := schnorr.Sign(privateKey, hash[:])
	if err != nil {
		t.Fatalf("sign delegation token: %v", err)
	}
	return hex.EncodeToString(sig.Serialize())
}
