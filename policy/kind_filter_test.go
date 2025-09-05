// policy/kind_filter_test.go
package policy

import (
	"context"
	"testing"

	"github.com/nbd-wtf/go-nostr"
	"github.com/stretchr/testify/require"
)

func TestKindFilter(t *testing.T) {
	// A small helper to create events with a specific kind for this test.
	makeTestEventWithKind := func(kind int) *nostr.Event {
		return &nostr.Event{Kind: kind, PubKey: "test_pubkey"}
	}

	testCases := []struct {
		name           string
		allowedKinds   []int
		deniedKinds    []int
		eventKind      int
		expectedAction string
	}{
		{
			name:           "Allowlist only: Kind is on the list",
			allowedKinds:   []int{1, 7},
			deniedKinds:    []int{},
			eventKind:      1,
			expectedAction: ActionAccept,
		},
		{
			name:           "Allowlist only: Kind is NOT on the list",
			allowedKinds:   []int{1, 7},
			deniedKinds:    []int{},
			eventKind:      3,
			expectedAction: ActionReject,
		},
		{
			name:           "Denylist only: Kind is on the list",
			allowedKinds:   []int{},
			deniedKinds:    []int{3, 9},
			eventKind:      3,
			expectedAction: ActionReject,
		},
		{
			name:           "Denylist only: Kind is NOT on the list",
			allowedKinds:   []int{},
			deniedKinds:    []int{3, 9},
			eventKind:      1,
			expectedAction: ActionAccept,
		},
		{
			name:           "Both lists: Kind is allowed and not denied",
			allowedKinds:   []int{1, 7},
			deniedKinds:    []int{3},
			eventKind:      7,
			expectedAction: ActionAccept,
		},
		{
			name:           "Both lists: Kind is on the denylist",
			allowedKinds:   []int{1, 7},
			deniedKinds:    []int{3},
			eventKind:      3,
			expectedAction: ActionReject,
		},
		{
			name:           "Denylist has priority: Kind is on both lists",
			allowedKinds:   []int{1, 3, 7},
			deniedKinds:    []int{3},
			eventKind:      3,
			expectedAction: ActionReject,
		},
		{
			name:           "Both lists: Kind is not on either list",
			allowedKinds:   []int{1, 7},
			deniedKinds:    []int{3},
			eventKind:      42,
			expectedAction: ActionReject,
		},
		{
			name:           "No lists configured: Any kind is allowed",
			allowedKinds:   []int{},
			deniedKinds:    []int{},
			eventKind:      10002,
			expectedAction: ActionAccept,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a new filter for each test case
			filter := NewKindFilter(tc.allowedKinds, tc.deniedKinds)
			event := makeTestEventWithKind(tc.eventKind)

			result := filter.Check(context.Background(), event, "127.0.0.1")

			require.Equal(t, tc.expectedAction, result.Action)
		})
	}
}
