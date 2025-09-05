// main_test.go
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"adresu-plugin/config"
	"adresu-plugin/policy"
	"adresu-plugin/testutils"

	"github.com/nbd-wtf/go-nostr"
)

// --- helpers ---

func writeTempConfig(t *testing.T, dir string, cfg *config.Config) string {
	t.Helper()

	// Ensure DB path is inside temp dir so tests don't touch real FS.
	cfg.DB.Path = filepath.Join(dir, "badgerdb")
	// Make size filter permissive to avoid incidental rejections.
	cfg.Filters.Size.DefaultMaxSize = 1024 * 1024
	// Disable potentially intrusive filters explicitly.
	cfg.Filters.RateLimiter.Enabled = false
	cfg.Filters.Language.Enabled = false
	cfg.Filters.EphemeralChat.Enabled = false
	cfg.Filters.RepostAbuse.Enabled = false
	cfg.Filters.Keywords.Enabled = false

	// Minimal policy requirements
	if cfg.Policy.BanDuration <= 0 {
		cfg.Policy.BanDuration = 24 * time.Hour
	}
	// IMPORTANT: BanEmoji/UnbanEmoji have defaults, so moderator_pubkey MUST be set.
	moderator := testutils.TestPubKey

	// Encode TOML manually using text; we only need the fields we changed.
	// Keeping it tiny avoids coupling to toml encoder in tests.
	text := "" +
		"[database]\n" +
		"path = " + strconvQuote(cfg.DB.Path) + "\n" +
		"\n" +
		"[policy]\n" +
		"ban_duration = " + strconvQuote(cfg.Policy.BanDuration.String()) + "\n" +
		"moderator_pubkey = " + strconvQuote(moderator) + "\n" +
		"\n" +
		"[filters.size]\n" +
		"default_max_size_bytes = " + "1048576" + "\n" +
		"\n" +
		"[filters.rate_limiter]\n" +
		"enabled = false\n" +
		"\n" +
		"[filters.language]\n" +
		"enabled = false\n" +
		"\n" +
		"[filters.ephemeral_chat]\n" +
		"enabled = false\n" +
		"\n" +
		"[filters.repost_abuse]\n" +
		"enabled = false\n" +
		"\n" +
		"[filters.keywords]\n" +
		"enabled = false\n"

	p := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		t.Fatalf("failed to write temp config: %v", err)
	}
	return p
}

func strconvQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// preparePipeline builds a pipeline using a temp config tailored for tests.
func preparePipeline(t *testing.T) (*policy.Pipeline, func()) {
	t.Helper()
	tmp := t.TempDir()
	cfg := &config.Config{}
	configPath := writeTempConfig(t, tmp, cfg)

	loaded, _, err := config.Load(configPath, false)
	if err != nil {
		t.Fatalf("config.Load failed: %v", err)
	}

	p, db, err := buildPipeline(loaded)
	if err != nil {
		t.Fatalf("buildPipeline failed: %v", err)
	}

	cleanup := func() {
		_ = db.Close()
	}

	return p, cleanup
}

// runProcess runs processEvents with provided lines and returns all output lines written.
func runProcess(t *testing.T, p *policy.Pipeline, lines [][]byte) ([][]byte, error) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	r, w := io.Pipe()
	rd := bufio.NewReader(r)

	pr, pw := io.Pipe() // writer for stdout of processEvents

	// feed input
	go func() {
		for _, ln := range lines {
			_, _ = w.Write(append(ln, '\n'))
		}
		w.Close()
	}()

	// collect output
	var out [][]byte
	errCh := make(chan error, 1)
	go func() {
		// process
		err := processEvents(ctx, rd, pw, p)
		_ = pw.Close()
		errCh <- err
	}()

	scanner := bufio.NewScanner(pr)
	for scanner.Scan() {
		cp := append([]byte(nil), scanner.Bytes()...)
		out = append(out, cp)
	}
	readErr := scanner.Err()
	procErr := <-errCh
	if readErr != nil {
		return out, readErr
	}
	return out, procErr
}

// --- tests ---

func TestBuildPipeline_Initializes(t *testing.T) {
	tmp := t.TempDir()
	cfg := &config.Config{}
	configPath := writeTempConfig(t, tmp, cfg)

	loaded, _, err := config.Load(configPath, false)
	if err != nil {
		t.Fatalf("config.Load failed: %v", err)
	}

	p, db, err := buildPipeline(loaded)
	if err != nil {
		t.Fatalf("buildPipeline error: %v", err)
	}
	if p == nil {
		t.Fatal("pipeline is nil")
	}
	if db == nil {
		t.Fatal("db is nil")
	}
	_ = db.Close()
}

func TestValidateConfiguration_ValidAndInvalid(t *testing.T) {
	tmp := t.TempDir()

	// valid
	validPath := writeTempConfig(t, tmp, &config.Config{})
	if err := validateConfiguration(validPath); err != nil {
		t.Fatalf("validateConfiguration(valid) unexpected error: %v", err)
	}

	// invalid: set non-positive cache_ttl in repost_abuse to trigger validation error
	invalidText := "" +
		"[database]\n" +
		"path = " + strconvQuote(filepath.Join(tmp, "db2")) + "\n" +
		"\n" +
		"[policy]\n" +
		"ban_duration = " + strconvQuote("24h") + "\n" +
		"moderator_pubkey = " + strconvQuote(testutils.TestPubKey) + "\n" +
		"\n" +
		"[filters.repost_abuse]\n" +
		"enabled = true\n" +
		"cache_ttl = " + strconvQuote("0s") + "\n"

	invalidPath := filepath.Join(tmp, "bad.toml")
	if err := os.WriteFile(invalidPath, []byte(invalidText), 0o600); err != nil {
		t.Fatalf("failed to write invalid config: %v", err)
	}
	if err := validateConfiguration(invalidPath); err == nil {
		t.Fatal("validateConfiguration(invalid) expected error, got nil")
	}
}

func TestProcessEvents_BasicAccept(t *testing.T) {
	p, cleanup := preparePipeline(t)
	defer cleanup()

	// Create a simple text-note event
	ev := testutils.MakeTextNote(testutils.TestPubKey, "hello", time.Now())

	in := struct {
		Event nostr.Event `json:"event"`
		IP    string      `json:"ip"`
	}{
		Event: *ev,
		IP:    "203.0.113.7",
	}
	b, _ := json.Marshal(in)

	outLines, err := runProcess(t, p, [][]byte{b})
	if err != nil {
		t.Fatalf("processEvents returned error: %v", err)
	}
	if len(outLines) != 1 {
		t.Fatalf("expected 1 output line, got %d", len(outLines))
	}

	var resp struct {
		ID     string `json:"id"`
		Action string `json:"action"`
		Msg    string `json:"msg"`
	}
	if err := json.Unmarshal(outLines[0], &resp); err != nil {
		t.Fatalf("failed to decode response: %v; raw=%s", err, string(outLines[0]))
	}

	if resp.ID != ev.ID {
		t.Fatalf("response id mismatch: want %s got %s", ev.ID, resp.ID)
	}
	// In permissive config the pipeline should accept a basic text note.
	if resp.Action != "accept" {
		t.Fatalf("expected action 'accept', got %q (msg=%q)", resp.Action, resp.Msg)
	}
}

func TestProcessEvents_IgnoresMalformedJSON(t *testing.T) {
	p, cleanup := preparePipeline(t)
	defer cleanup()

	lines := [][]byte{
		[]byte("{this is not json}"),
	}

	// Should not error; processEvents logs a warning and continues until EOF.
	out, err := runProcess(t, p, lines)
	if err != nil {
		// context will finish with nil since EOF on stdin is normal termination
		t.Fatalf("unexpected error from processEvents: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("expected no output lines for malformed input, got %d", len(out))
	}
}
