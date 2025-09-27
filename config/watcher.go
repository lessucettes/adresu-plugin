package config

import (
	"context"
	"log/slog"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

const defaultDebounceDelay = 500 * time.Millisecond

func StartWatcher(ctx context.Context, configPath string, onConfigReload func(*Config), debounceDelay time.Duration) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		slog.Error("Failed to create config file watcher", "error", err)
		return
	}
	defer watcher.Close()

	configDir := filepath.Dir(configPath)
	if err := watcher.Add(configDir); err != nil {
		slog.Error("Failed to add config path to watcher", "path", configDir, "error", err)
		return
	}

	delay := debounceDelay
	if delay <= 0 {
		delay = defaultDebounceDelay
	}

	slog.Info("Started configuration watcher", "path", configPath, "debounce", delay)

	var debounceTimer *time.Timer
	var mu sync.Mutex

	for {
		select {
		case <-ctx.Done():
			mu.Lock()
			if debounceTimer != nil {
				debounceTimer.Stop()
			}
			mu.Unlock()
			slog.Info("Stopping configuration watcher...")
			return

		case event, ok := <-watcher.Events:
			if !ok {
				slog.Warn("Watcher events channel closed unexpectedly, stopping watcher.")
				return
			}

			isRelevantEvent := event.Name == configPath &&
				(event.Has(fsnotify.Write) || event.Has(fsnotify.Create) || event.Has(fsnotify.Rename))

			if isRelevantEvent {
				mu.Lock()
				if debounceTimer != nil {
					debounceTimer.Stop()
				}
				debounceTimer = time.AfterFunc(delay, func() {
					slog.Info("Config file changed, attempting to reload...", "path", configPath)
					newCfg, _, err := Load(configPath, false)
					if err != nil {
						slog.Error("Failed to reload config file, keeping old configuration", "path", configPath, "error", err)
						return
					}

					onConfigReload(newCfg)
					slog.Info("Configuration reloaded and applied successfully", "path", configPath)
				})
				mu.Unlock()
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				slog.Warn("Watcher errors channel closed unexpectedly, stopping watcher.")
				return
			}
			slog.Error("Error watching config file", "error", err)
		}
	}
}
