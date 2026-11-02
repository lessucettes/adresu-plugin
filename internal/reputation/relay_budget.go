package reputation

import (
	"errors"
	"sync/atomic"
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
