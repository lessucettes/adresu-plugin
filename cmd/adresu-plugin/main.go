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
	"sync"
	"syscall"

	kitpolicy "github.com/lessucettes/adresu-plugin/pkg/adresu-kit/policy"
	"github.com/nbd-wtf/go-nostr"

	"github.com/lessucettes/adresu-plugin/internal/config"
	"github.com/lessucettes/adresu-plugin/internal/policy"
	"github.com/lessucettes/adresu-plugin/internal/store"
	"github.com/lessucettes/adresu-plugin/internal/strfry"
)

var version = "dev"

type PolicyInput struct {
	Type       string      `json:"type,omitempty"`
	Event      nostr.Event `json:"event"`
	SourceType string      `json:"sourceType,omitempty"`
	SourceInfo string      `json:"sourceInfo,omitempty"`
	IP         string      `json:"ip,omitempty"`
}

var (
	currentPipeline *policy.Pipeline
	pipelineMutex   sync.RWMutex
)

func buildPipeline(cfg *config.Config, db store.Store) (*policy.Pipeline, error) {
	strfryClient := strfry.NewClient(cfg.Strfry.ExecutablePath, cfg.Strfry.ConfigPath)

	var stages []policy.PipelineStage

	type kitFilterFactory struct {
		name        string
		constructor func() (kitpolicy.Filter, error)
	}

	langDetector := kitpolicy.GetGlobalDetector()

	kitFactories := []kitFilterFactory{
		{"EmergencyFilter", func() (kitpolicy.Filter, error) { return kitpolicy.NewEmergencyFilter(&cfg.Filters.Emergency) }},
		{"KindFilter", func() (kitpolicy.Filter, error) { return kitpolicy.NewKindFilter(&cfg.Filters.Kind) }},
		{"RateLimiterFilter", func() (kitpolicy.Filter, error) { return kitpolicy.NewRateLimiterFilter(&cfg.Filters.RateLimiter) }},
		{"FreshnessFilter", func() (kitpolicy.Filter, error) { return kitpolicy.NewFreshnessFilter(&cfg.Filters.Freshness) }},
		{"SizeFilter", func() (kitpolicy.Filter, error) { return kitpolicy.NewSizeFilter(&cfg.Filters.Size) }},
		{"TagsFilter", func() (kitpolicy.Filter, error) { return kitpolicy.NewTagsFilter(&cfg.Filters.Tags) }},
		{"KeywordFilter", func() (kitpolicy.Filter, error) { return kitpolicy.NewKeywordFilter(&cfg.Filters.Keywords) }},
		{"RepostAbuseFilter", func() (kitpolicy.Filter, error) { return kitpolicy.NewRepostAbuseFilter(&cfg.Filters.RepostAbuse) }},
		{"EphemeralChatFilter", func() (kitpolicy.Filter, error) { return kitpolicy.NewEphemeralChatFilter(&cfg.Filters.EphemeralChat) }},
		{"LanguageFilter", func() (kitpolicy.Filter, error) {
			return kitpolicy.NewLanguageFilter(&cfg.Filters.Language, langDetector)
		}},
	}

	for _, factory := range kitFactories {
		filter, err := factory.constructor()
		if err != nil {
			return nil, fmt.Errorf("failed to create kit filter '%s': %w", factory.name, err)
		}
		if filter != nil {
			stages = append(stages, policy.PipelineStage{Filter: filter})
		}
	}

	bannedAuthorFilter, err := policy.NewBannedAuthorFilter(db, &cfg.Filters.BannedAuthor)
	if err != nil {
		return nil, fmt.Errorf("failed to create BannedAuthorFilter: %w", err)
	}
	stages = append(stages, policy.PipelineStage{Filter: bannedAuthorFilter})

	moderationFilter, err := policy.NewModerationFilter(
		cfg.Policy.ModeratorPubKey, cfg.Policy.BanEmoji, cfg.Policy.UnbanEmoji, db, strfryClient, cfg.Policy.BanDuration,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create ModerationFilter: %w", err)
	}
	stages = append(stages, policy.PipelineStage{Filter: moderationFilter})

	autoBanFilter, err := policy.NewAutoBanFilter(db, &cfg.Filters.AutoBan)
	if err != nil {
		return nil, fmt.Errorf("failed to create AutoBanFilter: %w", err)
	}
	rejectionHandlers := []policy.RejectionHandler{autoBanFilter}

	var metricsCollector policy.MetricsCollector = nil
	pipeline := policy.NewPipeline(cfg, stages, rejectionHandlers, metricsCollector)

	return pipeline, nil
}

func main() {
	showVersion := flag.Bool("version", false, "Show plugin version and exit")
	configPath := flag.String("config", "./config.toml", "Path to the configuration file.")
	useDefaults := flag.Bool("use-defaults", false, "Run with internal defaults if the config file is missing.")
	validateConfig := flag.Bool("validate", false, "Validate the configuration file and exit.")
	dryRun := flag.Bool("dry-run", false, "Log what would be rejected without actually rejecting it.")
	flag.Parse()

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
		fmt.Fprintf(os.Stderr, "Application run failed: %v\n", err)
		os.Exit(1)
	}
}

func runApp(configPath string, useDefaults bool, dryRun bool) error {
	cfg, defaultsUsed, err := config.Load(configPath, useDefaults)
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: cfg.Log.Level.ToSlogLevel()}))
	slog.SetDefault(logger)
	if dryRun {
		slog.Warn("Plugin is running in DRY-RUN mode.")
	}
	slog.Info("Policy plugin starting up", "version", version, "config_path", configPath, "using_defaults", defaultsUsed)

	db, err := store.NewBadgerStore(&cfg.DB)
	if err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	}
	defer db.Close()

	p, err := buildPipeline(cfg, db)
	if err != nil {
		return err
	}

	pipelineMutex.Lock()
	currentPipeline = p
	pipelineMutex.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	shutdownChan := make(chan os.Signal, 1)
	signal.Notify(shutdownChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-shutdownChan
		slog.Info("Received shutdown signal, shutting down gracefully...")
		cancel()
	}()

	onReload := func(newCfg *config.Config) {
		slog.Info("Reloading pipeline with new configuration...")
		newPipeline, err := buildPipeline(newCfg, db)
		if err != nil {
			slog.Error("Failed to build new pipeline on config reload, keeping old one", "error", err)
			return
		}

		pipelineMutex.Lock()
		oldPipeline := currentPipeline
		currentPipeline = newPipeline
		pipelineMutex.Unlock()

		if oldPipeline != nil {
			go oldPipeline.Close() // Gracefully shutdown the old pipeline.
		}

		slog.Info("Pipeline reloaded successfully.", "path", configPath)
	}
	go config.StartWatcher(ctx, configPath, onReload, 0)

	return processEvents(ctx, os.Stdin, os.Stdout, dryRun)
}

func processEvents(ctx context.Context, r io.Reader, w io.Writer, dryRun bool) error {
	linesChan := make(chan []byte)
	errChan := make(chan error, 1)
	encoder := json.NewEncoder(w)

	go func() {
		defer close(errChan) // This ensures the error channel is always closed.
		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			lineCopy := make([]byte, len(scanner.Bytes()))
			copy(lineCopy, scanner.Bytes())
			linesChan <- lineCopy
		}
		if err := scanner.Err(); err != nil {
			errChan <- err
		}
		close(linesChan)
	}()

	slog.Info("Ready to process events from stdin...")
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case line, ok := <-linesChan:
			if !ok {
				// linesChan is closed, check for a final error. This no longer blocks.
				if err := <-errChan; err != nil {
					return err
				}
				slog.Info("Input stream closed, shutting down.")
				return nil
			}

			if len(line) == 0 {
				continue
			}
			var input PolicyInput
			if err := json.Unmarshal(line, &input); err != nil {
				slog.Warn("Failed to decode policy input JSON", "error", err, "raw_line_prefix", string(line))
				continue
			}

			remoteIP := ""
			if input.SourceType == "IP4" || input.SourceType == "IP6" {
				remoteIP = input.SourceInfo
			} else if input.IP != "" {
				remoteIP = input.IP
			}

			pipelineMutex.RLock()
			p := currentPipeline
			pipelineMutex.RUnlock()

			result, err := p.ProcessEvent(ctx, &input.Event, remoteIP, dryRun)
			if err != nil {
				slog.Error("Error processing event", "event_id", input.Event.ID, "error", err)
				continue
			}

			if err := encoder.Encode(result); err != nil {
				if errors.Is(err, os.ErrClosed) || errors.Is(err, syscall.EPIPE) {
					return nil
				}
				slog.Error("Failed to write response to stdout", "error", err)
			}
		}
	}
}

func validateConfiguration(configPath string) error {
	slog.SetDefault(slog.New(slog.NewJSONHandler(io.Discard, nil)))
	fmt.Printf("Validating configuration file: %s\n", configPath)
	cfg, _, err := config.Load(configPath, false)
	if err != nil {
		return err
	}

	db, err := store.NewBadgerStore(&cfg.DB)
	if err != nil {
		return fmt.Errorf("failed to open database for validation: %w", err)
	}
	defer db.Close()

	if _, err := buildPipeline(cfg, db); err != nil {
		return err
	}
	return nil
}
