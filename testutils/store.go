// testutils/store.go
package testutils

import (
	"context"
	"sync"
	"time"
)

type InMemoryStore struct {
	mu         sync.RWMutex
	bannedKeys map[string]time.Time
}

// NewInMemoryStore creates a new in-memory store.
func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		bannedKeys: make(map[string]time.Time),
	}
}

// IsAuthorBanned checks if a pubkey is in the in-memory ban map and handles expiry.
func (s *InMemoryStore) IsAuthorBanned(ctx context.Context, pubkey string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	expiry, found := s.bannedKeys[pubkey]
	if found && time.Now().After(expiry) {
		delete(s.bannedKeys, pubkey)
		return false, nil
	}
	return found, nil
}

// BanAuthor adds a pubkey to the in-memory ban map.
func (s *InMemoryStore) BanAuthor(ctx context.Context, pubkey string, duration time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bannedKeys[pubkey] = time.Now().Add(duration)
	return nil
}

// UnbanAuthor removes a pubkey from the in-memory ban map.
func (s *InMemoryStore) UnbanAuthor(ctx context.Context, pubkey string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.bannedKeys, pubkey)
	return nil
}

// Close is a no-op for the in-memory store.
func (s *InMemoryStore) Close() error {
	return nil
}

type MockStore struct {
	mu          sync.RWMutex
	banned      map[string]bool
	calls       int
	errToReturn error
}

func NewMockStore() *MockStore {
	return &MockStore{banned: make(map[string]bool)}
}

func (s *MockStore) SetError(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.errToReturn = err
}

func (s *MockStore) ClearError() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.errToReturn = nil
}

func (s *MockStore) Calls() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.calls
}

func (s *MockStore) IsAuthorBanned(ctx context.Context, pubkey string) (bool, error) {
	s.mu.Lock()
	s.calls++
	err := s.errToReturn
	s.mu.Unlock()
	if err != nil {
		return false, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.banned[pubkey], nil
}

func (s *MockStore) BanAuthor(ctx context.Context, pubkey string, duration time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.errToReturn != nil {
		return s.errToReturn
	}
	s.banned[pubkey] = true
	return nil
}

func (s *MockStore) UnbanAuthor(ctx context.Context, pubkey string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.errToReturn != nil {
		return s.errToReturn
	}
	delete(s.banned, pubkey)
	return nil
}

func (s *MockStore) Close() error {
	if s.errToReturn != nil {
		return s.errToReturn
	}
	return nil
}

// MockStoreWithSignal is a mock store that signals via channel when a ban occurs.
// Useful for testing asynchronous behavior without relying on time.Sleep.
type MockStoreWithSignal struct {
	mu        sync.RWMutex
	banned    map[string]bool
	BanCalls  int
	BanSignal chan string
}

func NewMockStoreWithSignal(bufferSize int) *MockStoreWithSignal {
	return &MockStoreWithSignal{
		banned:    make(map[string]bool),
		BanSignal: make(chan string, bufferSize),
	}
}

func (s *MockStoreWithSignal) IsAuthorBanned(ctx context.Context, pubkey string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.banned[pubkey], nil
}

func (s *MockStoreWithSignal) BanAuthor(ctx context.Context, pubkey string, duration time.Duration) error {
	s.mu.Lock()
	s.banned[pubkey] = true
	s.BanCalls++
	s.mu.Unlock()

	// notify test
	s.BanSignal <- pubkey
	return nil
}

func (s *MockStoreWithSignal) UnbanAuthor(ctx context.Context, pubkey string) error {
	return nil
}

func (s *MockStoreWithSignal) Close() error {
	return nil
}
