package strfry

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"time"
)

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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	filter := fmt.Sprintf(`{"authors":["%s"]}`, author)
	args := []string{
		"--config=" + c.configPath,
		"delete",
		"--filter=" + filter,
	}

	cmd := exec.CommandContext(ctx, c.executablePath, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	slog.Info("Executing strfry delete", "author", author, "command", cmd.String())

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("strfry delete command failed: %w, stderr: %s", err, stderr.String())
	}

	slog.Info("Successfully deleted events for author", "author", author)
	return nil
}
