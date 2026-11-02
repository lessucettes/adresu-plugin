package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"fiatjaf.com/nostr"
	"github.com/lessucettes/adresu-plugin/pkg/adresu-kit/nip"
	kitpolicy "github.com/lessucettes/adresu-plugin/pkg/adresu-kit/policy"
	kitrep "github.com/lessucettes/adresu-plugin/pkg/adresu-kit/reputation"

	"github.com/lessucettes/adresu-plugin/internal/config"
	"github.com/lessucettes/adresu-plugin/internal/policy"
	repservice "github.com/lessucettes/adresu-plugin/internal/reputation"
	"github.com/lessucettes/adresu-plugin/internal/store"
	"github.com/lessucettes/adresu-plugin/internal/strfry"
)

var version = "dev"

const maxPolicyResponseSize = 8 << 10 // strfry's plugin output record limit.

type PolicyInput struct {
	Type        string      `json:"type,omitempty"`
	Event       nostr.Event `json:"event"`
	SourceType  string      `json:"sourceType,omitempty"`
	SourceInfo  string      `json:"sourceInfo,omitempty"`
	IP          string      `json:"ip,omitempty"`
	eventID     string
	eventPubKey string
}

// UnmarshalJSON validates the wire fields before converting to binary types.
// The upstream Event decoder silently ignores invalid hex and truncates kinds.
func (p *PolicyInput) UnmarshalJSON(data []byte) error {
	type input PolicyInput
	var envelope struct {
		*input
		Event json.RawMessage `json:"event"`
	}
	envelope.input = (*input)(p)
	if err := json.Unmarshal(data, &envelope); err != nil {
		return err
	}
	var event struct {
		ID        string          `json:"id"`
		PubKey    string          `json:"pubkey"`
		CreatedAt nostr.Timestamp `json:"created_at"`
		Kind      uint16          `json:"kind"`
		Tags      nostr.Tags      `json:"tags"`
		Content   string          `json:"content"`
		Sig       string          `json:"sig"`
	}
	if err := json.Unmarshal(envelope.Event, &event); err != nil {
		return err
	}
	if !nostr.IsValid32ByteHex(strings.ToLower(event.ID)) {
		return errors.New("invalid event ID: expected 64 hex characters")
	}
	id, err := nostr.IDFromHex(event.ID)
	if err != nil {
		return fmt.Errorf("invalid event ID: %w", err)
	}
	if !nostr.IsValid32ByteHex(strings.ToLower(event.PubKey)) {
		return errors.New("invalid event pubkey: expected 64 hex characters")
	}
	pubkey, err := nostr.PubKeyFromHex(event.PubKey)
	if err != nil {
		return fmt.Errorf("invalid event pubkey: %w", err)
	}
	var sig [64]byte
	if len(event.Sig) != hex.EncodedLen(len(sig)) {
		return errors.New("invalid event signature length")
	}
	if _, err := hex.Decode(sig[:], []byte(event.Sig)); err != nil {
		return fmt.Errorf("invalid event signature: %w", err)
	}
	p.Event = nostr.Event{
		ID: id, PubKey: pubkey, CreatedAt: event.CreatedAt,
		Kind: nostr.Kind(event.Kind), Tags: event.Tags, Content: event.Content, Sig: sig,
	}
	p.eventID = event.ID
	p.eventPubKey = event.PubKey
	return nil
}

var (
	currentPipeline *policy.Pipeline
	pipelineMutex   sync.RWMutex
)

func reputationReader(manager *repservice.Manager, cfg *config.Config) (kitrep.Reader, error) {
	if !cfg.Filters.Reputation.Enabled {
		return nil, nil
	}
	return manager.Reader(cfg.Reputation)
}

func buildPipeline(cfg *config.Config, db store.Store, reputationReader kitrep.Reader) (*policy.Pipeline, error) {
	strfryClient := strfry.NewClient(cfg.Strfry.ExecutablePath, cfg.Strfry.ConfigPath)

	var filters []kitpolicy.Filter
	var rejectionHandlers []policy.RejectionHandler
	built := false
	defer func() {
		if !built {
			_ = policy.NewPipeline(cfg, filters, rejectionHandlers).Close()
		}
	}()

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
			filters = append(filters, filter)
		}
	}

	bannedAuthorFilter, err := policy.NewBannedAuthorFilter(db, &cfg.Filters.BannedAuthor)
	if err != nil {
		return nil, fmt.Errorf("failed to create BannedAuthorFilter: %w", err)
	}
	filters = append(filters, bannedAuthorFilter)

	reputationFilter, err := kitpolicy.NewReputationFilter(&cfg.Filters.Reputation, reputationReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create ReputationFilter: %w", err)
	}
	filters = append(filters, reputationFilter)

	moderationFilter, err := policy.NewModerationFilter(
		cfg.Policy.ModeratorPubKey, cfg.Policy.BanEmoji, cfg.Policy.UnbanEmoji, db, strfryClient, cfg.Policy.BanDuration,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create ModerationFilter: %w", err)
	}
	filters = append(filters, moderationFilter)

	autoBanFilter, err := policy.NewAutoBanFilter(db, &cfg.Filters.AutoBan)
	if err != nil {
		return nil, fmt.Errorf("failed to create AutoBanFilter: %w", err)
	}
	rejectionHandlers = []policy.RejectionHandler{autoBanFilter}

	pipeline := policy.NewPipeline(cfg, filters, rejectionHandlers)
	built = true

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
	// Configuration warnings precede discovery of the configured log level.
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	reputation := repservice.NewManager(ctx, db)
	defer reputation.Close()
	reader, err := reputationReader(reputation, cfg)
	if err != nil {
		return err
	}
	p, err := buildPipeline(cfg, db, reader)
	if err != nil {
		return err
	}
	if err := reputation.Configure(cfg.Reputation, cfg.Filters.Reputation.Enabled); err != nil {
		_ = p.Close()
		return err
	}

	pipelineMutex.Lock()
	currentPipeline = p
	pipelineMutex.Unlock()

	var retired sync.WaitGroup

	onReload := func(newCfg *config.Config) {
		slog.Info("Reloading pipeline with new configuration...")
		reader, err := reputationReader(reputation, newCfg)
		if err != nil {
			slog.Error("Invalid reputation configuration on reload", "error", err)
			return
		}
		newPipeline, err := buildPipeline(newCfg, db, reader)
		if err != nil {
			slog.Error("Failed to build new pipeline on config reload, keeping old one", "error", err)
			return
		}
		if err := reputation.Configure(newCfg.Reputation, newCfg.Filters.Reputation.Enabled); err != nil {
			_ = newPipeline.Close()
			slog.Error("Failed to reload reputation collector, keeping old pipeline", "error", err)
			return
		}

		pipelineMutex.Lock()
		oldPipeline := currentPipeline
		currentPipeline = newPipeline
		pipelineMutex.Unlock()

		if oldPipeline != nil {
			retired.Add(1)
			go func() {
				defer retired.Done()
				_ = oldPipeline.Close()
			}()
		}

		slog.Info("Pipeline reloaded successfully.", "path", configPath)
	}
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		config.StartWatcher(ctx, configPath, onReload, 0)
	}()
	defer func() {
		stop()
		<-watcherDone
		pipelineMutex.Lock()
		p := currentPipeline
		currentPipeline = nil
		pipelineMutex.Unlock()
		if p != nil {
			_ = p.Close()
		}
		retired.Wait()
	}()

	input, err := prepareStdin()
	if err != nil {
		return err
	}
	err = processEvents(ctx, input, os.Stdout, dryRun)
	if errors.Is(err, context.Canceled) && ctx.Err() != nil {
		return nil
	}
	return err
}

func processEvents(ctx context.Context, r io.Reader, w io.Writer, dryRun bool) error {
	ctx, cancel := context.WithCancel(ctx)
	linesChan := make(chan []byte)
	errChan := make(chan error, 1)
	readerDone := make(chan struct{})
	encoder := json.NewEncoder(w)
	defer func() {
		cancel()
		// Own closable input so shutdown also interrupts a blocked read.
		if closer, ok := r.(io.Closer); ok {
			_ = closer.Close()
			select {
			case <-readerDone:
			case <-time.After(200 * time.Millisecond):
				slog.Warn("Input reader did not stop after close")
			}
		}
	}()

	go func() {
		defer close(readerDone)
		defer close(linesChan)
		defer close(errChan)
		reader := bufio.NewReader(r)
		for {
			line, err := reader.ReadBytes('\n')
			if len(line) > 0 {
				select {
				case linesChan <- line:
				case <-ctx.Done():
					return
				}
			}
			if err != nil {
				if !errors.Is(err, io.EOF) {
					errChan <- err
				}
				return
			}
		}
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

			if len(bytes.TrimSpace(line)) == 0 {
				continue
			}
			var input PolicyInput
			if err := json.Unmarshal(line, &input); err != nil {
				decodeError := err.Error()
				if len(decodeError) > 1024 {
					decodeError = decodeError[:1024]
				}
				slog.Warn("Failed to decode policy input JSON", "error", decodeError,
					"raw_line_prefix", string(line[:min(len(line), 1024)]))
				// strfry accepts some event shapes that nostr.Event cannot decode
				// (for example, non-string tag extensions). Reply using the ID
				// decoded independently, or strfry waits until its plugin timeout.
				var envelope struct {
					Event struct {
						ID *string `json:"id"`
					} `json:"event"`
				}
				if json.Unmarshal(line, &envelope) == nil && envelope.Event.ID != nil {
					response := policy.PolicyResponse{ID: *envelope.Event.ID, Action: "reject", Msg: "invalid: Event could not be decoded."}
					if err := encoder.Encode(response); err != nil {
						if errors.Is(err, os.ErrClosed) || errors.Is(err, syscall.EPIPE) {
							return nil
						}
						return fmt.Errorf("failed to write policy response: %w", err)
					}
				}
				// A malformed request must not stop the plugin. Without a
				// string ID there is no correlated response we can send.
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

			eventCtx := nip.WithWirePubKey(ctx, &input.Event, input.eventPubKey)
			result, err := p.ProcessEvent(eventCtx, &input.Event, remoteIP, dryRun)
			pipelineMutex.RUnlock()
			// Correlate with strfry's exact input spelling, including uppercase hex.
			result.ID = input.eventID
			if err != nil {
				slog.Error("Error processing event", "event_id", input.eventID, "error", err)
			}

			// Long configured patterns can produce reasons beyond strfry's
			// record limit. Account for JSON escaping, retaining ordinary reasons.
			if len(result.Msg) > maxPolicyResponseSize/8 {
				raw, err := json.Marshal(result)
				if err != nil {
					return fmt.Errorf("failed to encode policy response: %w", err)
				}
				if len(raw)+1 > maxPolicyResponseSize {
					result.Msg = "Event rejected by relay policy; see relay logs for the detailed reason."
				}
			}
			if err := encoder.Encode(result); err != nil {
				if errors.Is(err, os.ErrClosed) || errors.Is(err, syscall.EPIPE) {
					return nil
				}
				return fmt.Errorf("failed to write policy response: %w", err)
			}
		}
	}
}

func validateConfiguration(configPath string) error {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})))
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

	// Validation constructs the filter without starting network collection.
	reputation := repservice.NewManager(context.Background(), db)
	defer reputation.Close()
	reader, err := reputationReader(reputation, cfg)
	if err != nil {
		return err
	}
	p, err := buildPipeline(cfg, db, reader)
	if err != nil {
		return err
	}
	return p.Close()
}
