// Package reputation integrates the reusable ranking engine with plugin storage
// and background collection. No worker is owned by an individual pipeline.
package reputation

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"fiatjaf.com/nostr"
	"github.com/lessucettes/adresu-plugin/internal/config"
	kitrep "github.com/lessucettes/adresu-plugin/pkg/adresu-kit/reputation"
)

type view struct {
	id       string
	cfg      config.ReputationConfig
	snapshot atomic.Pointer[kitrep.Snapshot]
}

// Manager owns one collector independently of pipeline reloads. All methods
// except the test-only source factory may be used concurrently.
type Manager struct {
	ctx       context.Context
	store     Store
	newSource func(config.ReputationConfig) Source
	current   atomic.Pointer[view]
	mu        sync.Mutex
	cancel    context.CancelFunc
	done      chan struct{}
	closed    bool
}

func NewManager(ctx context.Context, store Store) *Manager {
	return &Manager{ctx: ctx, store: store, newSource: func(cfg config.ReputationConfig) Source {
		if cfg.DiscoverRelays {
			return newDiscoverySource(cfg)
		}
		return relaySource{cfg: cfg}
	}}
}

// Reader is scoped to a graph configuration: retired pipelines cannot consume
// scores computed using a different set of trust anchors.
func (m *Manager) Reader(cfg config.ReputationConfig) (kitrep.Reader, error) {
	id, _, err := configurationID(cfg)
	return scopedReader{manager: m, id: id}, err
}

// Configure preserves the worker for policy-only reloads. A graph configuration
// change cancels and joins the old collector before starting its replacement.
// Database/network failures are handled in the worker and never block startup.
func (m *Manager) Configure(cfg config.ReputationConfig, enabled bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return errors.New("reputation manager is closed")
	}
	var id string
	var seeds []nostr.PubKey
	if enabled {
		var err error
		id, seeds, err = configurationID(cfg)
		if err != nil {
			return err
		}
		if m.store == nil || cfg.RefreshInterval <= 0 || cfg.MaxAge <= 0 || cfg.BatchSize <= 0 || cfg.MaxNodes < len(seeds) || cfg.MaxDepth <= 0 {
			return errors.New("invalid reputation worker configuration")
		}
		if active := m.current.Load(); active != nil && active.id == id {
			return nil
		}
	}
	m.stopLocked()
	if !enabled {
		return nil
	}
	cfg.Seeds = slices.Clone(cfg.Seeds)
	cfg.Relays = slices.Clone(cfg.Relays)
	cfg.DiscoveryRelays = slices.Clone(cfg.DiscoveryRelays)
	active := &view{id: id, cfg: cfg}
	m.current.Store(active)
	ctx, cancel := context.WithCancel(m.ctx)
	m.cancel, m.done = cancel, make(chan struct{})
	go m.run(ctx, active, seeds, m.newSource(cfg), m.done)
	return nil
}

func (m *Manager) stopLocked() {
	if m.cancel != nil {
		m.cancel()
		<-m.done
		m.cancel, m.done = nil, nil
	}
	m.current.Store(nil)
}

func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	m.stopLocked()
	return nil
}

type scopedReader struct {
	manager *Manager
	id      string
}

func (r scopedReader) Lookup(pk nostr.PubKey) kitrep.Assessment {
	active := r.manager.current.Load()
	if active == nil || active.id != r.id {
		return kitrep.Assessment{}
	}
	snapshot := active.snapshot.Load()
	now := time.Now()
	if snapshot == nil || snapshot.CalculatedAt.After(now) || now.Sub(snapshot.CalculatedAt) > active.cfg.MaxAge || !now.Before(snapshot.ValidUntil) {
		return kitrep.Assessment{}
	}
	score, found := snapshot.Scores[pk]
	return kitrep.Assessment{Score: score, Known: found, Ready: true}
}

func configurationID(cfg config.ReputationConfig) (string, []nostr.PubKey, error) {
	seeds := make([]nostr.PubKey, 0, len(cfg.Seeds))
	for _, text := range cfg.Seeds {
		pk, err := nostr.PubKeyFromHex(text)
		if err != nil || pk == nostr.ZeroPK {
			return "", nil, errors.New("invalid reputation seed public key")
		}
		if !slices.Contains(seeds, pk) {
			seeds = append(seeds, pk)
		}
	}
	if len(seeds) == 0 {
		return "", nil, errors.New("at least one reputation seed is required")
	}
	slices.SortFunc(seeds, func(a, b nostr.PubKey) int { return bytes.Compare(a[:], b[:]) })
	cfg.Seeds = make([]string, len(seeds))
	for i, pk := range seeds {
		cfg.Seeds[i] = pk.Hex()
	}
	cfg.Relays = slices.Clone(cfg.Relays)
	sort.Strings(cfg.Relays)
	cfg.Relays = slices.Compact(cfg.Relays)
	raw, err := json.Marshal(cfg)
	if err != nil {
		return "", nil, err
	}
	sum := sha256.Sum256(raw)
	return "v1:" + hex.EncodeToString(sum[:]), seeds, nil
}
