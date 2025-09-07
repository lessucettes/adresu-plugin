// main.go
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"adresu-plugin/config"
	"adresu-plugin/policy"
	"adresu-plugin/store"
	"adresu-plugin/strfry"

	"github.com/nbd-wtf/go-nostr"
)

// version is set at build time.
var version = "dev"

// PolicyInput models strfry's JSON line for policy plugins.
// Newer strfry sends source metadata via sourceType/sourceInfo,
// older setups may still send top-level "ip".
type PolicyInput struct {
	Type       string      `json:"type,omitempty"` // "new" | "lookback" (not used, but kept for completeness)
	Event      nostr.Event `json:"event"`
	ReceivedAt int64       `json:"receivedAt,omitempty"` // unix seconds (not used here)
	SourceType string      `json:"sourceType,omitempty"` // "IP4" | "IP6" | "Import" | "Stream" | "Sync" | "Stored"
	SourceInfo string      `json:"sourceInfo,omitempty"` // IP or relay URL depending on sourceType

	// Back-compat with very old strfry/bridges that emitted { ip: "..." } at top-level
	IP string `json:"ip,omitempty"`
}

// PolicyResponse defines the structure of the JSON output for strfry.
type PolicyResponse struct {
	ID     string `json:"id"`
	Action string `json:"action"`
	Msg    string `json:"msg,omitempty"`
}

func main() {
	// --- Flag Definition ---
	showVersion := flag.Bool("version", false, "Show plugin version and exit")
	configPath := flag.String("config", "./config.toml", "Path to the configuration file.")
	useDefaults := flag.Bool("use-defaults", false, "Run with internal defaults if the config file is missing.")
	validateConfig := flag.Bool("validate", false, "Validate the configuration file and exit.")
	dryRun := flag.Bool("dry-run", false, "Log what would be rejected without actually rejecting it.")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "adresu-plugin: A policy plugin for strfry (version: %s).\n\n", version)
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	// --- Mode Dispatch ---
	if *showVersion {
		fmt.Println(version)
		return
	}

	if *validateConfig {
		if err := validateConfiguration(*configPath); err != nil {
			fmt.Fprintf(os.Stderr, "Configuration is INVALID: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Configuration is VALID.")
		return
	}

	if err := runApp(*configPath, *useDefaults, *dryRun); err != nil {
		// Logger might not be initialized yet, so use fmt for this final error.
		fmt.Fprintf(os.Stderr, "Application run failed: %v\n", err)
		os.Exit(1)
	}
}

// buildPipeline initializes and wires up all major application components.
// It returns the policy pipeline, the database connection, and any startup error.
func buildPipeline(cfg *config.Config) (*policy.Pipeline, store.Store, error) {
	db, err := store.NewBadgerStore(cfg.DB.Path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize database: %w", err)
	}

	strfryClient := strfry.NewClient(cfg.Strfry.ExecutablePath, cfg.Strfry.ConfigPath)

	keywordFilter, err := policy.NewKeywordFilter(&cfg.Filters.Keywords)
	if err != nil {
		db.Close() // Clean up the DB connection if a later step fails.
		return nil, nil, fmt.Errorf("failed to create KeywordFilter: %w", err)
	}

	languageDetector := policy.GetGlobalDetector()

	pipeline := policy.NewPipeline(
		policy.NewAutoBanFilter(db, &cfg.Filters.AutoBan),
		policy.NewKindFilter(cfg.Policy.AllowedKinds, cfg.Policy.DeniedKinds),
		policy.NewBannedAuthorFilter(db, &cfg.Filters.BannedAuthor),
		policy.NewRateLimiterFilter(&cfg.Filters.RateLimiter),
		policy.NewFreshnessFilter(&cfg.Filters.Freshness),
		policy.NewRepostAbuseFilter(&cfg.Filters.RepostAbuse),
		policy.NewSizeFilter(&cfg.Filters.Size),
		policy.NewTagsFilter(&cfg.Filters.Tags),
		keywordFilter,
		policy.NewLanguageFilter(&cfg.Filters.Language, languageDetector),
		policy.NewEphemeralChatFilter(&cfg.Filters.EphemeralChat),
		policy.NewModerationFilter(
			cfg.Policy.ModeratorPubKey,
			cfg.Policy.BanEmoji,
			cfg.Policy.UnbanEmoji,
			db,
			strfryClient,
			cfg.Policy.BanDuration,
		),
	)

	return pipeline, db, nil
}

// validateConfiguration loads and validates the config file, then exits.
func validateConfiguration(configPath string) error {
	// Mute all logging during validation for clean output.
	silentLogger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	slog.SetDefault(silentLogger)

	fmt.Printf("Validating configuration file: %s\n", configPath)

	cfg, _, err := config.Load(configPath, false)
	if err != nil {
		return err
	}

	// Attempt to build the full pipeline to validate all components.
	_, db, err := buildPipeline(cfg)
	if err != nil {
		return err
	}

	// The DB connection is not needed further in validation mode.
	db.Close()
	return nil
}

// runApp is the main application entry point.
func runApp(configPath string, useDefaults bool, dryRun bool) error {
	// --- Configuration & Logging ---
	cfg, defaultsUsed, err := config.Load(configPath, useDefaults)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: cfg.Log.Level.ToSlogLevel(),
	}))
	slog.SetDefault(logger)

	if dryRun {
		slog.Warn("Plugin is running in DRY-RUN mode. All 'reject' actions will be logged but not enforced.")
	}

	slog.Info("Policy plugin starting up",
		"version", version,
		"config_path", configPath,
		"using_defaults", defaultsUsed,
	)

	// --- Dependencies & Pipeline ---
	pipeline, db, err := buildPipeline(cfg)
	if err != nil {
		return err
	}
	defer db.Close()

	// --- Graceful Shutdown Setup ---
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	shutdownChan := make(chan os.Signal, 1)
	signal.Notify(shutdownChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		sig := <-shutdownChan
		slog.Info("Received shutdown signal, shutting down gracefully...", "signal", sig.String())
		cancel()
	}()

	// --- Background Services ---
	var updatableFilters []config.UpdatableFilter
	for _, f := range pipeline.Filters() {
		if updatable, ok := f.(config.UpdatableFilter); ok {
			updatableFilters = append(updatableFilters, updatable)
		}
	}
	go config.StartWatcher(ctx, configPath, updatableFilters, 0)

	// --- Main Event Loop ---
	return processEvents(ctx, os.Stdin, os.Stdout, pipeline, dryRun)
}

// processEvents runs the main I/O loop, processing events from stdin
// and writing responses to stdout. It's designed to be cancellable via the context.
func processEvents(ctx context.Context, r io.Reader, w io.Writer, p *policy.Pipeline, dryRun bool) error {
	linesChan := make(chan []byte)
	errChan := make(chan error, 1)
	encoder := json.NewEncoder(w)

	// Start a scanner in a separate goroutine to avoid blocking the main loop.
	go func() {
		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			line := scanner.Bytes()
			lineCopy := make([]byte, len(line))
			copy(lineCopy, line)
			linesChan <- lineCopy
		}
		// Report the final status (nil on clean EOF, or an error).
		errChan <- scanner.Err()
	}()

	slog.Info("Ready to process events from stdin...")

	const maxLogLineLength = 256 // Max length of a raw line to log on error.

	for {
		select {
		case <-ctx.Done():
			slog.Info("Context canceled, shutting down event processing.")
			return ctx.Err()

		case err := <-errChan:
			if err != nil {
				slog.Error("Error reading from stdin", "error", err)
				return err
			}
			slog.Info("Input stream closed, shutting down.")
			return nil

		case line := <-linesChan:
			if len(line) == 0 {
				continue
			}

			var input PolicyInput
			if err := json.Unmarshal(line, &input); err != nil {
				truncatedLine := string(line)
				if len(truncatedLine) > maxLogLineLength {
					truncatedLine = truncatedLine[:maxLogLineLength]
				}
				slog.Warn("Failed to decode policy input JSON", "error", err, "raw_line_prefix", truncatedLine)
				continue
			}

			// Derive remote IP from modern or legacy fields.
			remoteIP := ""
			switch input.SourceType {
			case "IP4", "IP6":
				remoteIP = input.SourceInfo
			}
			if remoteIP == "" && input.IP != "" { // legacy fallback
				remoteIP = input.IP
			}

			result := p.ProcessEvent(ctx, &input.Event, remoteIP, dryRun)

			response := PolicyResponse{
				ID:     input.Event.ID,
				Action: result.Action,
				Msg:    result.Message,
			}

			if err := encoder.Encode(response); err != nil {
				if errors.Is(err, os.ErrClosed) || errors.Is(err, syscall.EPIPE) {
					slog.Warn("Stdout pipe closed by the parent process, shutting down.", "error", err)
					return nil // Clean shutdown condition.
				}
				slog.Error("Failed to write response to stdout", "error", err)
			}
		}
	}
}
