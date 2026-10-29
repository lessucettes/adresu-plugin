package config

import (
	"context"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
)

const defaultDebounceDelay = 500 * time.Millisecond

// StartWatcher watches the directory containing configPath for changes and
// calls onConfigReload with a freshly loaded and validated configuration.
//
// It blocks until ctx is cancelled. Reloads run synchronously in the watcher
// goroutine: StartWatcher does not return while onConfigReload is executing,
// and reload callbacks can never overlap, so a stale configuration cannot
// overwrite a newer one.
func StartWatcher(ctx context.Context, configPath string, onConfigReload func(*Config), debounceDelay time.Duration) {
	if onConfigReload == nil {
		slog.Error("Config watcher requires a reload callback", "path", configPath)
		return
	}

	// fsnotify builds event names from the path passed to Add, so normalize
	// the configured path once and compare absolute, cleaned names. Otherwise
	// a relative path such as "config.toml" never matches its events, which
	// arrive as "./config.toml".
	absConfigPath, err := filepath.Abs(configPath)
	if err != nil {
		slog.Error("Failed to resolve config path", "path", configPath, "error", err)
		return
	}
	absConfigPath = filepath.Clean(absConfigPath)

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		slog.Error("Failed to create config file watcher", "error", err)
		return
	}
	defer watcher.Close()

	configDir := filepath.Dir(absConfigPath)
	if resolvedDir, err := filepath.EvalSymlinks(configDir); err == nil {
		configDir = resolvedDir
	}
	watchedConfigPath := filepath.Join(configDir, filepath.Base(absConfigPath))
	if err := watcher.Add(configDir); err != nil {
		slog.Error("Failed to add config path to watcher", "path", configDir, "error", err)
		return
	}

	// Watch both the configured link and its target's directory. Directory
	// watches survive atomic file replacement; refresh the target when a link
	// is replaced and remove the old watch so repeated reloads do not leak it.
	targetPath := watchedConfigPath
	refreshTarget := func() bool {
		resolved, err := filepath.EvalSymlinks(absConfigPath)
		if err != nil || resolved == targetPath {
			return false
		}
		oldDir, newDir := filepath.Dir(targetPath), filepath.Dir(resolved)
		if newDir != configDir && newDir != oldDir {
			if err := watcher.Add(newDir); err != nil {
				slog.Error("Failed to watch config symlink target", "path", newDir, "error", err)
				return false
			}
		}
		if oldDir != configDir && oldDir != newDir {
			_ = watcher.Remove(oldDir)
		}
		targetPath = resolved
		return true
	}
	refreshTarget()

	delay := debounceDelay
	if delay <= 0 {
		delay = defaultDebounceDelay
	}

	slog.Info("Started configuration watcher", "path", absConfigPath, "debounce", delay)

	timer := time.NewTimer(delay)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			timer.Stop()
			// Drain a value that may already have been delivered; the reload
			// it represents is intentionally skipped during shutdown.
			select {
			case <-timer.C:
			default:
			}
			slog.Info("Stopping configuration watcher...")
			return

		case event, ok := <-watcher.Events:
			if !ok {
				slog.Warn("Watcher events channel closed unexpectedly, stopping watcher.")
				return
			}

			targetChanged := refreshTarget()
			if !targetChanged && !isConfigFileEvent(event, watchedConfigPath) && !isConfigFileEvent(event, targetPath) {
				continue
			}

			// Reset the debounce window. This goroutine is the only receiver
			// on timer.C, so draining it here is safe.
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(delay)

		case <-timer.C:
			if ctx.Err() != nil {
				// The watcher was cancelled while the debounce window was
				// pending; do not apply a configuration during shutdown.
				slog.Info("Stopping configuration watcher...")
				return
			}

			refreshTarget()
			slog.Info("Config file changed, attempting to reload...", "path", absConfigPath)
			newCfg, _, err := Load(absConfigPath, false)
			if err != nil {
				slog.Error("Failed to reload config file, keeping old configuration", "path", absConfigPath, "error", err)
				continue
			}

			onConfigReload(newCfg)
			slog.Info("Configuration reloaded and applied successfully", "path", absConfigPath)

		case err, ok := <-watcher.Errors:
			if !ok {
				slog.Warn("Watcher errors channel closed unexpectedly, stopping watcher.")
				return
			}
			slog.Error("Error watching config file", "error", err)
		}
	}
}

// isConfigFileEvent reports whether event represents a write, creation or
// rename of the watched configuration file. Paths are compared in absolute,
// cleaned form because fsnotify preserves the path spelling given to Add.
func isConfigFileEvent(event fsnotify.Event, absConfigPath string) bool {
	if !event.Has(fsnotify.Write) && !event.Has(fsnotify.Create) && !event.Has(fsnotify.Rename) {
		return false
	}

	eventPath, err := filepath.Abs(event.Name)
	if err != nil {
		return false
	}
	return filepath.Clean(eventPath) == absConfigPath
}
