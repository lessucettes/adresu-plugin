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
	delegationTag := event.Tags.Find("delegation")
	if delegationTag == nil {
		return "", fmt.Errorf("event has no delegation tag")
	}

	if len(delegationTag) != 4 {
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
				kind, err := strconv.Atoi(v)
				if err != nil {
					return fmt.Errorf("invalid 'kind' condition value: %q", v)
				}
				if event.Kind == kind {
					kindMatch = true
					break
				}
			}
			if !kindMatch {
				return fmt.Errorf("event kind %d is not in the allowed list", event.Kind)
			}
		case "created_at>":
			ts, err := strconv.ParseInt(values[0], 10, 64)
			if err != nil {
				return fmt.Errorf("invalid 'created_at>' value: %q", values[0])
			}
			if int64(event.CreatedAt) <= ts {
				return fmt.Errorf("event created_at %d is not after %d", event.CreatedAt, ts)
			}
		case "created_at<":
			ts, err := strconv.ParseInt(values[0], 10, 64)
			if err != nil {
				return fmt.Errorf("invalid 'created_at<' value: %q", values[0])
			}
			if int64(event.CreatedAt) >= ts {
				return fmt.Errorf("event created_at %d is not before %d", event.CreatedAt, ts)
			}
		}
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
