package nip

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/nbd-wtf/go-nostr"
)

func ValidateDelegation(event *nostr.Event) (string, error) {
	if event == nil {
		return "", fmt.Errorf("event is nil")
	}

	delegationTag := event.Tags.Find("delegation")
	if delegationTag == nil {
		return "", fmt.Errorf("event has no delegation tag")
	}

	return ValidateDelegationTag(event, delegationTag)
}

// ValidateDelegationTag validates a specific NIP-26 delegation tag. Callers
// that inspect more than the first tag (an event may carry several) must use
// this instead of ValidateDelegation, which only reads the first tag.
func ValidateDelegationTag(event *nostr.Event, delegationTag nostr.Tag) (string, error) {
	if event == nil {
		return "", fmt.Errorf("event is nil")
	}
	if len(delegationTag) != 4 || delegationTag[0] != "delegation" {
		return "", fmt.Errorf("tag is not a valid delegation tag")
	}
	delegatorPubKeyHex := delegationTag[1]
	conditionsStr := delegationTag[2]
	sigHex := delegationTag[3]

	if err := validateDelegationConditions(event, conditionsStr); err != nil {
		return "", fmt.Errorf("event does not satisfy conditions: %w", err)
	}

	if err := verifyDelegationSignature(event.PubKey, delegatorPubKeyHex, conditionsStr, sigHex); err != nil {
		return "", fmt.Errorf("signature verification failed: %w", err)
	}

	return delegatorPubKeyHex, nil
}

func validateDelegationConditions(event *nostr.Event, conditionsStr string) error {
	var (
		hasKindConditions bool
		kindMatched       bool
	)

	// NIP-26 conditions are a query string, but the created_at operators are
	// part of the key (created_at<1234) rather than a key/value pair, so
	// url.ParseQuery would silently drop them.
	for _, rawCondition := range strings.Split(conditionsStr, "&") {
		if rawCondition == "" {
			continue
		}

		condition, err := url.QueryUnescape(strings.ReplaceAll(rawCondition, "+", "%2B"))
		if err != nil {
			return fmt.Errorf("failed to parse condition %q: %w", rawCondition, err)
		}

		switch {
		case strings.HasPrefix(condition, "kind="):
			hasKindConditions = true
			kind, err := strconv.Atoi(strings.TrimPrefix(condition, "kind="))
			if err != nil {
				return fmt.Errorf("invalid 'kind' condition value: %q", condition)
			}
			if event.Kind == kind {
				kindMatched = true
			}
		case strings.HasPrefix(condition, "created_at>"):
			ts, err := strconv.ParseInt(strings.TrimPrefix(condition, "created_at>"), 10, 64)
			if err != nil {
				return fmt.Errorf("invalid 'created_at>' condition value: %q", condition)
			}
			if int64(event.CreatedAt) <= ts {
				return fmt.Errorf("event created_at %d is not after %d", event.CreatedAt, ts)
			}
		case strings.HasPrefix(condition, "created_at<"):
			ts, err := strconv.ParseInt(strings.TrimPrefix(condition, "created_at<"), 10, 64)
			if err != nil {
				return fmt.Errorf("invalid 'created_at<' condition value: %q", condition)
			}
			if int64(event.CreatedAt) >= ts {
				return fmt.Errorf("event created_at %d is not before %d", event.CreatedAt, ts)
			}
		default:
			// Fail closed: an unenforceable condition must not be treated as
			// permission to sign on the delegator's behalf.
			return fmt.Errorf("unsupported condition %q", condition)
		}
	}

	if hasKindConditions && !kindMatched {
		return fmt.Errorf("event kind %d is not in the allowed list", event.Kind)
	}
	return nil
}

func verifyDelegationSignature(delegateePubKey, delegatorPubKeyHex, conditions, sigHex string) error {
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
