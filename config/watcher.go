// config/watcher.go
package config

import (
	"context"
	"log/slog"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// UpdatableFilter defines an interface for filters that support hot-reloading.
type UpdatableFilter interface {
	Name() string
	UpdateConfig(cfg *Config) error
}

const defaultDebounceDelay = 500 * time.Millisecond

// StartWatcher starts a goroutine that watches the config file for changes.
func StartWatcher(ctx context.Context, configPath string, filters []UpdatableFilter, debounceDelay time.Duration) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		slog.Error("Failed to create config file watcher", "error", err)
		return
	}
	defer func() {
		if err := watcher.Close(); err != nil {
			slog.Error("Failed to close watcher", "error", err)
		}
	}()

	configDir := filepath.Dir(configPath)
	err = watcher.Add(configDir)
	if err != nil {
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

					for _, f := range filters {
						if err := f.UpdateConfig(newCfg); err != nil {
							slog.Error("Failed to update filter configuration",
								"path", configPath, "filter", f.Name(), "error", err)
						} else {
							slog.Debug("Filter configuration updated successfully", "filter", f.Name())
						}
					}
					slog.Info("Configuration reloaded successfully", "path", configPath)
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
