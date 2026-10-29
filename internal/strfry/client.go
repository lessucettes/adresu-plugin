package strfry

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os/exec"
	"time"
)

const (
	deleteCommandTimeout   = 30 * time.Second
	deleteCommandWaitDelay = 5 * time.Second
	maxStderrBytes         = 8 << 10
)

// boundedBuffer keeps subprocess error output from growing without limit.
type boundedBuffer struct {
	buf   bytes.Buffer
	limit int
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if remaining := b.limit - b.buf.Len(); remaining > 0 {
		if len(p) > remaining {
			b.buf.Write(p[:remaining])
		} else {
			b.buf.Write(p)
		}
	}
	return len(p), nil
}

func (b *boundedBuffer) String() string {
	return b.buf.String()
}

type ClientInterface interface {
	DeleteEventsByAuthor(author string) error
}

type Client struct {
	executablePath string
	configPath     string
}

var _ ClientInterface = (*Client)(nil)

func NewClient(executablePath, configPath string) *Client {
	return &Client{
		executablePath: executablePath,
		configPath:     configPath,
	}
}

// DeleteEventsByAuthor calls `strfry delete` for a given author.
func (c *Client) DeleteEventsByAuthor(author string) error {
	if err := validateAuthor(author); err != nil {
		return fmt.Errorf("strfry delete: %w", err)
	}

	filter, err := json.Marshal(struct {
		Authors []string `json:"authors"`
	}{Authors: []string{author}})
	if err != nil {
		return fmt.Errorf("strfry delete: encode filter: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), deleteCommandTimeout)
	defer cancel()

	args := []string{
		"--config=" + c.configPath,
		"delete",
		"--filter=" + string(filter),
	}

	cmd := exec.CommandContext(ctx, c.executablePath, args...)
	// WaitDelay bounds cmd.Wait when a descendant keeps the stderr pipe open
	// after the direct child was killed on timeout.
	cmd.WaitDelay = deleteCommandWaitDelay
	stderr := &boundedBuffer{limit: maxStderrBytes}
	cmd.Stderr = stderr

	slog.Info("Executing strfry delete", "author", author, "command", cmd.String())

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("strfry delete command failed: %w, stderr: %s", err, stderr.String())
	}

	slog.Info("Successfully deleted events for author", "author", author)
	return nil
}

// validateAuthor rejects anything that is not a 32-byte hex public key so the
// author cannot break out of the JSON filter passed to strfry.
func validateAuthor(author string) error {
	if len(author) != 64 {
		return fmt.Errorf("invalid author pubkey %q", author)
	}
	if _, err := hex.DecodeString(author); err != nil {
		return fmt.Errorf("invalid author pubkey %q: %w", author, err)
	}
	return nil
}
