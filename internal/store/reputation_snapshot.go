package store

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/lessucettes/adresu-plugin/pkg/adresu-kit/reputation"
)

const (
	reputationSnapshotManifestKey = "reputation-snapshot:manifest"
	reputationSnapshotChunkPrefix = "reputation-snapshot:chunk:"

	snapshotFormatVersion      = 1
	snapshotChunkEntries       = 512
	snapshotGenerationHexBytes = 16
	snapshotChunkIndexHexWidth = 8

	maxSnapshotScores        = 1_000_000
	maxSnapshotChunks        = (maxSnapshotScores + snapshotChunkEntries - 1) / snapshotChunkEntries
	maxSnapshotNodes         = 10_000_000
	maxSnapshotEdges         = 100_000_000
	maxSnapshotChunkBytes    = 8 << 20
	maxSnapshotManifestBytes = 1 << 20
	maxSnapshotConfigIDBytes = 4 << 10

	snapshotCleanupBatch     = 256
	snapshotCleanupTimeout   = 5 * time.Second
	snapshotGenerationHexLen = snapshotGenerationHexBytes * 2
)

// snapshotManifest is the generation pointer. It is committed in one small
// transaction after every chunk is durable, so a failed save leaves the
// previous generation and its pointer intact.
type snapshotManifest struct {
	Format       int       `json:"format"`
	Generation   string    `json:"generation"`
	ChunkEntries int       `json:"chunk_entries"`
	ChunkCount   int       `json:"chunk_count"`
	ScoreCount   int       `json:"score_count"`
	ChunkDigest  string    `json:"chunk_digest"`
	ConfigID     string    `json:"config_id"`
	CalculatedAt time.Time `json:"calculated_at"`
	ValidUntil   time.Time `json:"valid_until"`
	Coverage     float64   `json:"coverage"`
	Nodes        int       `json:"nodes"`
	Edges        int       `json:"edges"`
}

// scoreRecord keeps binary public keys out of JSON maps. Chunks are arrays of
// these records, in no particular order; completeness is enforced by the
// manifest's score count and digest.
type scoreRecord struct {
	PubKey    string  `json:"pubkey"`
	PageRank  float64 `json:"page_rank"`
	TrustRank float64 `json:"trust_rank"`
}

func snapshotChunkKey(generation string, index int) []byte {
	return []byte(fmt.Sprintf("%s%s:%08x", reputationSnapshotChunkPrefix, generation, index))
}

// parseSnapshotChunkKey extracts a generation from one of our chunk keys.
// Malformed keys under the prefix are ignored rather than deleted.
func parseSnapshotChunkKey(key []byte) (string, bool) {
	encoded := string(key)
	if !strings.HasPrefix(encoded, reputationSnapshotChunkPrefix) {
		return "", false
	}
	rest := encoded[len(reputationSnapshotChunkPrefix):]
	if len(rest) != snapshotGenerationHexLen+1+snapshotChunkIndexHexWidth {
		return "", false
	}
	generation := rest[:snapshotGenerationHexLen]
	if rest[snapshotGenerationHexLen] != ':' || !validSnapshotGeneration(generation) {
		return "", false
	}
	if _, err := strconv.ParseUint(rest[snapshotGenerationHexLen+1:], 16, 32); err != nil {
		return "", false
	}
	return generation, true
}

func validSnapshotGeneration(generation string) bool {
	if len(generation) != snapshotGenerationHexLen || generation != strings.ToLower(generation) {
		return false
	}
	_, err := hex.DecodeString(generation)
	return err == nil
}

func newSnapshotGeneration() (string, error) {
	raw := make([]byte, snapshotGenerationHexBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate snapshot generation: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

func addSnapshotChunkDigest(digest hash.Hash, index int, data []byte) {
	var encodedIndex [8]byte
	binary.BigEndian.PutUint64(encodedIndex[:], uint64(index))
	_, _ = digest.Write(encodedIndex[:])
	_, _ = digest.Write(data)
}

func finiteNonNegative(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= 0
}

func validCoverage(coverage float64) bool {
	return finiteNonNegative(coverage) && coverage <= 1
}

func validateReputationScore(score reputation.Score) error {
	if !finiteNonNegative(score.PageRank) {
		return fmt.Errorf("page rank must be finite and nonnegative, got %v", score.PageRank)
	}
	if !finiteNonNegative(score.TrustRank) {
		return fmt.Errorf("trust rank must be finite and nonnegative, got %v", score.TrustRank)
	}
	return nil
}

func validateSnapshotForSave(snapshot *reputation.Snapshot) error {
	if snapshot.CalculatedAt.IsZero() {
		return errors.New("calculated_at must not be zero")
	}
	// The loader rejects overlong ConfigIDs, so a generation carrying one
	// must never be written: it would be unreadable after publication.
	if len(snapshot.ConfigID) > maxSnapshotConfigIDBytes {
		return fmt.Errorf("config ID is %d bytes, maximum is %d", len(snapshot.ConfigID), maxSnapshotConfigIDBytes)
	}
	if !validCoverage(snapshot.Coverage) {
		return fmt.Errorf("coverage must be finite and in [0,1], got %v", snapshot.Coverage)
	}
	if snapshot.Nodes < 0 || snapshot.Nodes > maxSnapshotNodes {
		return fmt.Errorf("node count %d is outside [0,%d]", snapshot.Nodes, maxSnapshotNodes)
	}
	if snapshot.Edges < 0 || snapshot.Edges > maxSnapshotEdges {
		return fmt.Errorf("edge count %d is outside [0,%d]", snapshot.Edges, maxSnapshotEdges)
	}
	if len(snapshot.Scores) > maxSnapshotScores {
		return fmt.Errorf("score count %d exceeds maximum %d", len(snapshot.Scores), maxSnapshotScores)
	}
	if len(snapshot.Scores) > snapshot.Nodes {
		return fmt.Errorf("score count %d exceeds node count %d", len(snapshot.Scores), snapshot.Nodes)
	}
	for pubkey, score := range snapshot.Scores {
		if err := validateReputationScore(score); err != nil {
			return fmt.Errorf("score for %s: %w", pubkey.Hex(), err)
		}
	}
	return nil
}

func validateSnapshotManifest(manifest snapshotManifest) error {
	if manifest.Format != snapshotFormatVersion {
		return fmt.Errorf("unsupported snapshot format %d", manifest.Format)
	}
	if !validSnapshotGeneration(manifest.Generation) {
		return fmt.Errorf("invalid snapshot generation %q", manifest.Generation)
	}
	if manifest.ChunkEntries != snapshotChunkEntries {
		return fmt.Errorf("snapshot chunk size %d does not match format %d", manifest.ChunkEntries, snapshotFormatVersion)
	}
	if manifest.ScoreCount < 0 || manifest.ScoreCount > maxSnapshotScores {
		return fmt.Errorf("snapshot score count %d is outside [0,%d]", manifest.ScoreCount, maxSnapshotScores)
	}
	expectedChunks := (manifest.ScoreCount + manifest.ChunkEntries - 1) / manifest.ChunkEntries
	if manifest.ChunkCount != expectedChunks || manifest.ChunkCount > maxSnapshotChunks {
		return fmt.Errorf("snapshot chunk count %d does not match %d scores", manifest.ChunkCount, manifest.ScoreCount)
	}
	if len(manifest.ChunkDigest) != sha256.Size*2 {
		return fmt.Errorf("snapshot chunk digest has length %d, want %d", len(manifest.ChunkDigest), sha256.Size*2)
	}
	if manifest.CalculatedAt.IsZero() {
		return errors.New("snapshot calculated_at must not be zero")
	}
	if !validCoverage(manifest.Coverage) {
		return fmt.Errorf("snapshot coverage must be finite and in [0,1], got %v", manifest.Coverage)
	}
	if manifest.Nodes < 0 || manifest.Nodes > maxSnapshotNodes {
		return fmt.Errorf("snapshot node count %d is outside [0,%d]", manifest.Nodes, maxSnapshotNodes)
	}
	if manifest.Edges < 0 || manifest.Edges > maxSnapshotEdges {
		return fmt.Errorf("snapshot edge count %d is outside [0,%d]", manifest.Edges, maxSnapshotEdges)
	}
	if len(manifest.ConfigID) > maxSnapshotConfigIDBytes {
		return fmt.Errorf("snapshot config ID is %d bytes, maximum is %d", len(manifest.ConfigID), maxSnapshotConfigIDBytes)
	}
	return nil
}
