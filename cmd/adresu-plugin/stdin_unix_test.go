//go:build unix

package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"testing"
	"time"

	"fiatjaf.com/nostr"
	kitpolicy "github.com/lessucettes/adresu-plugin/pkg/adresu-kit/policy"
)

func TestInheritedStdinCancellation(t *testing.T) {
	if os.Getenv("ADRESU_TEST_STDIN_CANCEL") == "1" {
		installTestPipeline(t, func(*nostr.Event) (kitpolicy.FilterResult, error) {
			return kitpolicy.FilterResult{Allowed: true}, nil
		})
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
		defer stop()
		input, err := prepareStdin()
		if err != nil {
			os.Exit(3)
		}
		err = processEvents(ctx, input, os.Stdout, false)
		if errors.Is(err, context.Canceled) {
			os.Exit(0)
		}
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestInheritedStdinCancellation$")
	cmd.Env = append(os.Environ(), "ADRESU_TEST_STDIN_CANCEL=1")
	var diagnostics bytes.Buffer
	cmd.Stderr = &diagnostics
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	if _, err := fmt.Fprintln(input, testPolicyLine("ready")); err != nil {
		t.Fatal(err)
	}
	if !bufio.NewScanner(output).Scan() {
		t.Fatal("child did not process input")
	}
	// Keep the write end open: EOF must not masquerade as signal cancellation.
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("stdin cancellation did not terminate cleanly: %v (context: %v)", err, ctx.Err())
	}
	if bytes.Contains(diagnostics.Bytes(), []byte("Input reader did not stop")) {
		t.Fatal("stdin reader was abandoned instead of interrupted")
	}
}
