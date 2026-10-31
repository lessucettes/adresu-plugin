//go:build unix

package main

import (
	"fmt"
	"os"
	"syscall"
	"time"
)

// prepareStdin takes ownership of stdin and makes inherited pipes cancelable.
// NewFile only registers an inherited descriptor with the runtime poller when
// O_NONBLOCK is already set. Do not change this shared flag for terminals.
func prepareStdin() (*os.File, error) {
	input := os.Stdin
	if input.SetReadDeadline(time.Time{}) == nil {
		return input, nil
	}
	info, err := input.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect stdin: %w", err)
	}
	if info.Mode()&(os.ModeNamedPipe|os.ModeSocket) == 0 {
		return input, nil
	}

	fd, err := syscall.Dup(int(input.Fd()))
	if err != nil {
		return nil, fmt.Errorf("duplicate stdin: %w", err)
	}
	syscall.CloseOnExec(fd)
	if err := syscall.SetNonblock(fd, true); err != nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("make stdin nonblocking: %w", err)
	}
	pollable := os.NewFile(uintptr(fd), input.Name())
	if err := pollable.SetReadDeadline(time.Time{}); err != nil {
		_ = pollable.Close()
		return nil, fmt.Errorf("register stdin with runtime poller: %w", err)
	}
	if err := input.Close(); err != nil {
		_ = pollable.Close()
		return nil, fmt.Errorf("close original stdin: %w", err)
	}
	return pollable, nil
}
