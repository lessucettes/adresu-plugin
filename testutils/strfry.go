// testutils/strfry.go
package testutils

import "sync"

// MockStrfryClient is a mock implementation of strfry.ClientInterface.
// It includes a channel to signal when an async operation is complete.
type MockStrfryClient struct {
	mu             sync.Mutex
	DeletedAuthors []string
	DeleteSignal   chan string
}

func NewMockStrfryClient(bufferSize int) *MockStrfryClient {
	return &MockStrfryClient{
		DeleteSignal: make(chan string, bufferSize),
	}
}

func (c *MockStrfryClient) DeleteEventsByAuthor(author string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.DeletedAuthors = append(c.DeletedAuthors, author)
	c.DeleteSignal <- author
	return nil
}
