// nip/13_pow.go
package nip

import (
	"math/bits"
	"strconv"
	"strings"

	"github.com/nbd-wtf/go-nostr"
)

var hexToLeadingZeros [256]int

func init() {
	for i := range 256 {
		char := byte(i)
		var val uint64
		if char >= '0' && char <= '9' {
			val, _ = strconv.ParseUint(string(char), 16, 4)
		} else if char >= 'a' && char <= 'f' {
			val, _ = strconv.ParseUint(string(char), 16, 4)
		} else if char >= 'A' && char <= 'F' {
			val, _ = strconv.ParseUint(string(char), 16, 4)
		} else {
			hexToLeadingZeros[i] = -1
			continue
		}
		if val == 0 {
			hexToLeadingZeros[i] = 4
		} else {
			hexToLeadingZeros[i] = bits.LeadingZeros8(uint8(val << 4))
		}
	}
}

// CountLeadingZeroBits calculates the number of leading zero bits in a hex string.
func CountLeadingZeroBits(hexString string) int {
	count := 0
	for i := 0; i < len(hexString); i++ {
		char := hexString[i]
		zeros := hexToLeadingZeros[char]
		if zeros == -1 {
			return count
		}
		count += zeros
		if zeros != 4 {
			break
		}
	}
	return count
}

// IsPoWValid checks if an event has a valid Proof of Work of at least minDifficulty.
func IsPoWValid(event *nostr.Event, minDifficulty int) bool {
	if minDifficulty <= 0 {
		return true
	}
	nonceTag := event.Tags.FindLast("nonce")
	if len(nonceTag) < 3 {
		return false
	}
	claimedDifficulty, err := strconv.Atoi(strings.TrimSpace(nonceTag[2]))
	if err != nil {
		return false
	}
	if claimedDifficulty < minDifficulty {
		return false
	}
	actualDifficulty := CountLeadingZeroBits(event.ID)
	return actualDifficulty >= claimedDifficulty
}
