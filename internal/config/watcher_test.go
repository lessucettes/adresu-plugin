package config

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

const moderatorKey = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

func configBody(banDuration string) string {
	return "[policy]\nmoderator_pubkey = \"" + moderatorKey + "\"\nban_duration = \"" + banDuration + "\"\n"
}

func TestStartWatcherFollowsConfigSymlink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	target := filepath.Join(t.TempDir(), "actual.toml")
	writeFile(t, target, configBody("24h"))
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	reloads := make(chan time.Duration, 8)
	done := make(chan struct{})
	go func() {
		defer close(done)
		StartWatcher(ctx, path, func(cfg *Config) { reloads <- cfg.Policy.BanDuration }, 10*time.Millisecond)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("symlink watcher did not stop")
		}
	})
	waitReload := func(want time.Duration) {
		t.Helper()
		timeout := time.NewTimer(3 * time.Second)
		defer timeout.Stop()
		for {
			select {
			case got := <-reloads:
				if got == want {
					return
				}
			case <-timeout.C:
				t.Fatalf("symlink watcher did not load ban duration %v", want)
			}
		}
	}
	time.Sleep(100 * time.Millisecond)
	writeFile(t, target, configBody("48h"))
	waitReload(48 * time.Hour)

	// Replacing the link must move the watch, not keep tracking its old target.
	nextTarget := filepath.Join(t.TempDir(), "next.toml")
	writeFile(t, nextTarget, configBody("49h"))
	if err := os.Symlink(nextTarget, path+".new"); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".new", path); err != nil {
		t.Fatal(err)
	}
	waitReload(49 * time.Hour)
	writeFile(t, nextTarget, configBody("50h"))
	waitReload(50 * time.Hour)
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// TestStartWatcherReloadsRelativePath guards against comparing raw fsnotify
// event names with the configured path: with a relative "config.toml" the
// events arrive as "./config.toml".
func TestStartWatcherReloadsRelativePath(t *testing.T) {
	t.Chdir(t.TempDir())

	writeFile(t, "config.toml", configBody("24h"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reloads := make(chan *Config, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		StartWatcher(ctx, "config.toml", func(cfg *Config) { reloads <- cfg }, 10*time.Millisecond)
	}()

	time.Sleep(100 * time.Millisecond) // let the watcher register its directory
	writeFile(t, "config.toml", configBody("48h"))

	select {
	case cfg := <-reloads:
		if cfg.Policy.BanDuration != 48*time.Hour {
			t.Fatalf("reloaded ban_duration = %v, want 48h", cfg.Policy.BanDuration)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("watcher did not reload the config through a relative path")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("watcher did not stop after context cancellation")
	}
}

// TestStartWatcherWaitsForRunningReload ensures StartWatcher does not return
// (and thus does not let callers close the database) while a reload callback is
// still executing.
func TestStartWatcherWaitsForRunningReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	writeFile(t, path, configBody("24h"))

	ctx, cancel := context.WithCancel(context.Background())
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})

	go func() {
		defer close(done)
		StartWatcher(ctx, path, func(*Config) {
			close(entered)
			<-release
		}, 10*time.Millisecond)
	}()

	time.Sleep(100 * time.Millisecond)
	writeFile(t, path, configBody("48h"))

	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("reload callback was not invoked")
	}

	cancel()

	select {
	case <-done:
		t.Fatal("StartWatcher returned while the reload callback was still running")
	case <-time.After(150 * time.Millisecond):
	}

	close(release)

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("StartWatcher did not return after the reload callback finished")
	}
}

// TestStartWatcherSerializesReloads verifies that a burst of writes cannot run
// two reload callbacks concurrently, which could apply an older config last.
func TestStartWatcherSerializesReloads(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	writeFile(t, path, configBody("24h"))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var inFlight, maxInFlight, reloads atomic.Int32
	done := make(chan struct{})

	go func() {
		defer close(done)
		StartWatcher(ctx, path, func(*Config) {
			reloads.Add(1)
			n := inFlight.Add(1)
			for {
				max := maxInFlight.Load()
				if n <= max || maxInFlight.CompareAndSwap(max, n) {
					break
				}
			}
			time.Sleep(200 * time.Millisecond)
			inFlight.Add(-1)
		}, 10*time.Millisecond)
	}()

	time.Sleep(100 * time.Millisecond)
	for _, body := range []string{configBody("25h"), configBody("26h"), configBody("27h")} {
		writeFile(t, path, body)
		time.Sleep(60 * time.Millisecond)
	}

	deadline := time.Now().Add(3 * time.Second)
	for reloads.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if reloads.Load() == 0 {
		t.Fatal("watcher did not reload after writes")
	}
	// Allow any (incorrect) concurrent callbacks to overlap.
	time.Sleep(400 * time.Millisecond)

	if got := maxInFlight.Load(); got > 1 {
		t.Fatalf("reload callbacks ran concurrently: max in flight = %d", got)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("watcher did not stop")
	}
}
