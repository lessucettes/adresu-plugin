// policy/banned_author_filter_test.go
package policy

import (
	"adresu-plugin/testutils"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestBannedAuthorFilter_Logic(t *testing.T) {
	ctx := context.Background()
	bannedKey := "banned_pubkey"
	cleanKey := "clean_pubkey"

	testCases := []struct {
		name           string
		pubkey         string
		setupStore     func(context.Context, *testutils.MockStore)
		expectedAction string
		expectedMsg    string
	}{
		{
			name:   "accepts event from a non-banned author",
			pubkey: cleanKey,
			setupStore: func(ctx context.Context, s *testutils.MockStore) {
				s.ClearError()
				// не баним cleanKey
			},
			expectedAction: ActionAccept,
		},
		{
			name:   "rejects event from a banned author",
			pubkey: bannedKey,
			setupStore: func(ctx context.Context, s *testutils.MockStore) {
				s.ClearError()
				_ = s.BanAuthor(ctx, bannedKey, time.Minute)
			},
			expectedAction: ActionReject,
			expectedMsg:    "blocked: author banned_pubkey is banned",
		},
		{
			name:   "rejects event if store returns an error",
			pubkey: "any_key",
			setupStore: func(ctx context.Context, s *testutils.MockStore) {
				s.SetError(errors.New("db is down"))
			},
			expectedAction: ActionReject,
			expectedMsg:    "internal: database error",
		},
	}

	for _, tc := range testCases {
		tc := tc // захват переменной
		t.Run(tc.name, func(t *testing.T) {
			s := testutils.NewMockStore()
			tc.setupStore(ctx, s)

			filter := NewBannedAuthorFilter(s)
			ev := testutils.MakeEvent(1, "content", tc.pubkey, time.Now())

			res := filter.Check(ctx, ev, "127.0.0.1")
			require.Equal(t, tc.expectedAction, res.Action)
			if res.Action == ActionReject {
				require.Contains(t, res.Message, tc.expectedMsg)
			}
		})
	}
}

func TestBannedAuthorFilter_Caching(t *testing.T) {
	ctx := context.Background()
	s := testutils.NewMockStore()
	s.ClearError()

	filter := NewBannedAuthorFilter(s)

	bannedKey := "banned_pubkey_for_cache_test"
	_ = s.BanAuthor(ctx, bannedKey, time.Minute)

	ev := testutils.MakeEvent(1, "x", bannedKey, time.Now())

	// Первый вызов — обращение к store
	filter.Check(ctx, ev, "127.0.0.1")
	require.Equal(t, 1, s.Calls(), "store должен вызваться один раз")

	// Второй вызов — результат из кэша
	filter.Check(ctx, ev, "127.0.0.1")
	require.Equal(t, 1, s.Calls(), "store не должен вызываться повторно")
}

func TestBannedAuthorFilter_Concurrency(t *testing.T) {
	// Не используем t.Parallel(), чтобы не пересекаться с другими тестами MockStore
	ctx := context.Background()
	s := testutils.NewMockStore()
	s.ClearError()

	filter := NewBannedAuthorFilter(s)

	bannedKey := "concurrent_banned_key"
	cleanKey := "concurrent_clean_key"
	_ = s.BanAuthor(ctx, bannedKey, time.Minute)

	var wg sync.WaitGroup
	const N = 100
	wg.Add(N)

	for i := 0; i < N; i++ {
		go func(i int) {
			defer wg.Done()
			key := cleanKey
			if i%2 == 0 {
				key = bannedKey
			}
			ev := testutils.MakeEvent(1, "x", key, time.Now())
			_ = filter.Check(ctx, ev, "127.0.0.1")
		}(i)
	}
	wg.Wait()

	// Для каждого уникального pubkey store должен был спросить только один раз
	require.Equal(t, 2, s.Calls(), "store должен вызваться ровно по одному разу на каждый ключ")
}
