// Package reputation provides local follow-graph rankings without plugin or storage dependencies.
package reputation

import (
	"time"

	"fiatjaf.com/nostr"
)

// FollowList is the latest verified kind-3 event for an author. An empty Follows
// slice is a real empty list, not a failed or missing lookup.
type FollowList struct {
	Author    nostr.PubKey
	EventID   nostr.ID
	CreatedAt nostr.Timestamp
	FetchedAt time.Time
	Follows   []nostr.PubKey
}

// Score contains the normalized probability mass of trust from the seeds.
type Score struct {
	TrustRank float64
}

// Options controls convergence of the TrustRank power-iteration algorithm.
type Options struct {
	Damping       float64
	Tolerance     float64
	MaxIterations int
}

// Result is a complete calculation over one graph.
type Result struct {
	Scores map[nostr.PubKey]Score
	Nodes  int
	Edges  int
}

// Snapshot is a complete persisted generation. Owners must not mutate Scores
// after publishing the snapshot to concurrent readers.
type Snapshot struct {
	ConfigID     string
	CalculatedAt time.Time
	ValidUntil   time.Time
	Coverage     float64
	Nodes        int
	Edges        int
	Scores       map[nostr.PubKey]Score
}

// Assessment distinguishes a known author from an unavailable ranking snapshot.
type Assessment struct {
	Score Score
	Known bool
	Ready bool
}

// Reader supplies a nonblocking local assessment to a policy filter. It does
// not imply a particular collector, database, application or network service.
type Reader interface {
	Lookup(nostr.PubKey) Assessment
}
