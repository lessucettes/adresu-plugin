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

	kitpolicy "github.com/lessucettes/adresu-kit/policy"
	"github.com/lessucettes/adresu-plugin/config"
	"github.com/lessucettes/adresu-plugin/policy"
	"github.com/lessucettes/adresu-plugin/store"
	"github.com/lessucettes/adresu-plugin/strfry"

	"github.com/nbd-wtf/go-nostr"
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

func buildPipeline(cfg *config.Config) (*policy.Pipeline, store.Store, error) {
	db, err := store.NewBadgerStore(cfg.DB.Path)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize database: %w", err)
	}

	strfryClient := strfry.NewClient(cfg.Strfry.ExecutablePath, cfg.Strfry.ConfigPath)

	var stages []policy.PipelineStage

	type filterFactory struct {
		name        string
		constructor func() (policy.Filter, []string, error)
	}

	langDetector := kitpolicy.GetGlobalDetector()

	factories := []filterFactory{
		{"KindFilter", func() (policy.Filter, []string, error) {
			return kitpolicy.NewKindFilter(&cfg.Filters.Kind)
		}},
		{"EmergencyFilter", func() (policy.Filter, []string, error) {
			return kitpolicy.NewEmergencyFilter(&cfg.Filters.Emergency)
		}},
		{"RateLimiterFilter", func() (policy.Filter, []string, error) {
			return kitpolicy.NewRateLimiterFilter(&cfg.Filters.RateLimiter)
		}},
		{"FreshnessFilter", func() (policy.Filter, []string, error) {
			return kitpolicy.NewFreshnessFilter(&cfg.Filters.Freshness)
		}},
		{"SizeFilter", func() (policy.Filter, []string, error) {
			return kitpolicy.NewSizeFilter(&cfg.Filters.Size)
		}},
		{"TagsFilter", func() (policy.Filter, []string, error) {
			return kitpolicy.NewTagsFilter(&cfg.Filters.Tags)
		}},
		{"KeywordFilter", func() (policy.Filter, []string, error) {
			return kitpolicy.NewKeywordFilter(&cfg.Filters.Keywords)
		}},
		{"RepostAbuseFilter", func() (policy.Filter, []string, error) {
			return kitpolicy.NewRepostAbuseFilter(&cfg.Filters.RepostAbuse)
		}},
		{"EphemeralChatFilter", func() (policy.Filter, []string, error) {
			return kitpolicy.NewEphemeralChatFilter(&cfg.Filters.EphemeralChat)
		}},
		{"LanguageFilter", func() (policy.Filter, []string, error) {
			return kitpolicy.NewLanguageFilter(&cfg.Filters.Language, langDetector)
		}},
	}

	for _, factory := range factories {
		filter, warns, err := factory.constructor()
		if err != nil {
			db.Close()
			return nil, nil, fmt.Errorf("failed to create %s: %w", factory.name, err)
		}
		if len(warns) > 0 {
			for _, w := range warns {
				slog.Warn("Configuration warning", "filter", factory.name, "message", w)
			}
		}
		if filter != nil {
			stages = append(stages, policy.PipelineStage{Name: factory.name, Filter: filter})
		}
	}

	bannedAuthorFilter := policy.NewBannedAuthorFilter(db, &cfg.Filters.BannedAuthor)
	stages = append(stages, policy.PipelineStage{Name: "BannedAuthorFilter", Filter: bannedAuthorFilter})

	moderationFilter := policy.NewModerationFilter(
		cfg.Policy.ModeratorPubKey, cfg.Policy.BanEmoji, cfg.Policy.UnbanEmoji, db, strfryClient, cfg.Policy.BanDuration,
	)
	stages = append(stages, policy.PipelineStage{Name: "ModerationFilter", Filter: moderationFilter})

	autoBanFilter := policy.NewAutoBanFilter(db, &cfg.Filters.AutoBan)
	pipeline := policy.NewPipeline(cfg, stages, autoBanFilter)

	return pipeline, db, nil
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

	p, db, err := buildPipeline(cfg)
	if err != nil {
		return err
	}
	defer db.Close()

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
		newPipeline, _, err := buildPipeline(newCfg)
		if err != nil {
			slog.Error("Failed to build new pipeline on config reload, keeping old one", "error", err)
			return
		}

		pipelineMutex.Lock()
		currentPipeline = newPipeline
		pipelineMutex.Unlock()
		slog.Info("Pipeline reloaded successfully.")
	}
	go config.StartWatcher(ctx, configPath, onReload, 0)

	return processEvents(ctx, os.Stdin, os.Stdout, dryRun)
}

func processEvents(ctx context.Context, r io.Reader, w io.Writer, dryRun bool) error {
	linesChan := make(chan []byte)
	errChan := make(chan error, 1)
	encoder := json.NewEncoder(w)

	go func() {
		scanner := bufio.NewScanner(r)
		for scanner.Scan() {
			lineCopy := make([]byte, len(scanner.Bytes()))
			copy(lineCopy, scanner.Bytes())
			linesChan <- lineCopy
		}
		errChan <- scanner.Err()
	}()

	slog.Info("Ready to process events from stdin...")
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errChan:
			if err != nil {
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

			result := p.ProcessEvent(ctx, &input.Event, remoteIP, dryRun)

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
	_, db, err := buildPipeline(cfg)
	if err != nil {
		return err
	}
	db.Close()
	return nil
}
