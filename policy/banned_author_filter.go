// policy/banned_author_filter.go
package policy

import (
	"adresu-plugin/config"
	"adresu-plugin/store"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	lru "github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/nbd-wtf/go-nostr"
	"golang.org/x/sync/singleflight"
)

const (
	defaultCacheSize = 8192
	defaultCacheTTL  = 5 * time.Minute
)

// BannedAuthorFilter checks if an event's author or delegator is banned.
type BannedAuthorFilter struct {
	store store.Store
	cache *lru.LRU[string, bool]
	mu    sync.RWMutex
	sf    singleflight.Group
	cfg   *config.BannedAuthorFilterConfig
}

func NewBannedAuthorFilter(s store.Store, cfg *config.BannedAuthorFilterConfig) *BannedAuthorFilter {
	cache := lru.NewLRU[string, bool](defaultCacheSize, nil, defaultCacheTTL)
	return &BannedAuthorFilter{
		store: s,
		cache: cache,
		cfg:   cfg,
	}
}

func (f *BannedAuthorFilter) Name() string { return "BannedAuthorFilter" }

func (f *BannedAuthorFilter) isBanned(ctx context.Context, pubkey string) (bool, error) {
	normalizedPubkey := strings.ToLower(pubkey)

	f.mu.RLock()
	if isBanned, ok := f.cache.Get(normalizedPubkey); ok {
		f.mu.RUnlock()
		return isBanned, nil
	}
	f.mu.RUnlock()

	v, err, _ := f.sf.Do(normalizedPubkey, func() (any, error) {
		f.mu.RLock()
		if isBanned, ok := f.cache.Get(normalizedPubkey); ok {
			f.mu.RUnlock()
			return isBanned, nil
		}
		f.mu.RUnlock()

		isBanned, err := f.store.IsAuthorBanned(ctx, normalizedPubkey)
		if err != nil {
			return false, err
		}

		f.mu.Lock()
		f.cache.Add(normalizedPubkey, isBanned)
		f.mu.Unlock()
		return isBanned, nil
	})

	if err != nil {
		return false, err
	}
	return v.(bool), nil
}

func (f *BannedAuthorFilter) Check(ctx context.Context, event *nostr.Event, remoteIP string) *Result {
	// The core relay (strfry) guarantees that the event reaching this plugin
	// has already passed full cryptographic verification.
	if event == nil {
		return Reject("blocked: invalid event")
	}

	// Always check the direct signer of the event.
	banned, err := f.isBanned(ctx, event.PubKey)
	if err != nil {
		slog.Error("Failed to check author ban status, rejecting (fail-closed)", "pubkey", event.PubKey, "error", err)
		return Reject("internal: verification error")
	}
	if banned {
		return Reject(fmt.Sprintf("blocked: author %s is banned", event.PubKey))
	}

	// Optionally check for NIP-26 delegation.
	if f.cfg != nil && f.cfg.CheckNIP26 {
		if delegationTag := event.Tags.Find("delegation"); delegationTag != nil {
			delegator, err := f.validateDelegation(event, delegationTag)
			if err != nil {
				return Reject(
					fmt.Sprintf("blocked: invalid delegation: %v", err),
					slog.String("delegation_error", err.Error()),
				)
			}

			if delegator != "" {
				banned, err := f.isBanned(ctx, delegator)
				if err != nil {
					slog.Error("Failed to check delegator ban status, rejecting (fail-closed)", "delegator", delegator, "error", err)
					return Reject("internal: verification error")
				}
				if banned {
					return Reject(
						fmt.Sprintf("blocked: delegator %s is banned", delegator),
						slog.String("delegator_pubkey", delegator),
						slog.String("signer_pubkey", event.PubKey),
					)
				}
			}
		}
	}

	return Accept()
}

// validateDelegation performs full NIP-26 validation: semantic and cryptographic.
func (f *BannedAuthorFilter) validateDelegation(event *nostr.Event, tag nostr.Tag) (string, error) {
	if len(tag) != 4 || tag[0] != "delegation" {
		return "", fmt.Errorf("tag is not a valid delegation tag")
	}
	delegatorPubKeyHex := tag[1]
	conditionsStr := tag[2]
	sigHex := tag[3]

	if err := f.validateDelegationConditions(event, conditionsStr); err != nil {
		return "", fmt.Errorf("event does not satisfy conditions: %w", err)
	}

	if err := f.verifyDelegationSignature(event.PubKey, delegatorPubKeyHex, conditionsStr, sigHex); err != nil {
		return "", fmt.Errorf("signature verification failed: %w", err)
	}

	return delegatorPubKeyHex, nil
}

func (f *BannedAuthorFilter) validateDelegationConditions(event *nostr.Event, conditionsStr string) error {
	safeConditionsStr := strings.ReplaceAll(conditionsStr, "+", "%2B")
	conditions, err := url.ParseQuery(safeConditionsStr)
	if err != nil {
		return fmt.Errorf("failed to parse conditions query string: %w", err)
	}

	for key, values := range conditions {
		if len(values) == 0 {
			continue
		}

		switch key {
		case "kind":
			kindMatch := false
			for _, v := range values {
				parts := strings.Split(v, ",")
				for _, part := range parts {
					kind, err := strconv.Atoi(part)
					if err != nil {
						return fmt.Errorf("invalid 'kind' condition value: %q", part)
					}
					if event.Kind == kind {
						kindMatch = true
						break
					}
				}
				if kindMatch {
					break
				}
			}
			if !kindMatch {
				return fmt.Errorf("event kind %d is not in the allowed list", event.Kind)
			}
		case "created_at>":
			for _, v := range values {
				ts, err := strconv.ParseInt(v, 10, 64)
				if err != nil {
					return fmt.Errorf("invalid 'created_at>' condition value: %q", v)
				}
				if int64(event.CreatedAt) <= ts {
					return fmt.Errorf("event created_at %d is not after required timestamp %d", event.CreatedAt, ts)
				}
			}
		case "created_at<":
			for _, v := range values {
				ts, err := strconv.ParseInt(v, 10, 64)
				if err != nil {
					return fmt.Errorf("invalid 'created_at<' condition value: %q", v)
				}
				if int64(event.CreatedAt) >= ts {
					return fmt.Errorf("event created_at %d is not before required timestamp %d", event.CreatedAt, ts)
				}
			}
		}
	}
	return nil
}

func (f *BannedAuthorFilter) verifyDelegationSignature(delegateePubKey, delegatorPubKeyHex, conditions, sigHex string) error {
	if len(delegateePubKey) != 64 {
		return fmt.Errorf("invalid delegatee pubkey length: %d", len(delegateePubKey))
	}
	if _, err := hex.DecodeString(delegateePubKey); err != nil {
		return fmt.Errorf("delegatee pubkey is not valid hex: %w", err)
	}
	if len(delegatorPubKeyHex) != 64 {
		return fmt.Errorf("invalid delegator pubkey length: %d", len(delegatorPubKeyHex))
	}
	if len(sigHex) != 128 {
		return fmt.Errorf("invalid signature length: %d", len(sigHex))
	}

	token := fmt.Sprintf("nostr:delegation:%s:%s", delegateePubKey, conditions)
	hash := sha256.Sum256([]byte(token))

	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		return fmt.Errorf("signature is not valid hex: %w", err)
	}
	sig, err := schnorr.ParseSignature(sigBytes)
	if err != nil {
		return fmt.Errorf("failed to parse schnorr signature: %w", err)
	}

	pubKeyBytes, err := hex.DecodeString(delegatorPubKeyHex)
	if err != nil {
		return fmt.Errorf("delegator pubkey is not valid hex: %w", err)
	}
	pubKey, err := schnorr.ParsePubKey(pubKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to parse delegator pubkey: %w", err)
	}

	if !sig.Verify(hash[:], pubKey) {
		return fmt.Errorf("schnorr signature is invalid")
	}

	return nil
}
