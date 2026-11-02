package policy

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"fiatjaf.com/nostr"

	"github.com/lessucettes/adresu-plugin/internal/config"
	kitpolicy "github.com/lessucettes/adresu-plugin/pkg/adresu-kit/policy"
)

type recordingFilter struct {
	mu      sync.Mutex
	metas   []map[string]any
	match   func(*nostr.Event) (kitpolicy.FilterResult, error)
	closed  atomic.Int32
	started chan struct{}
	block   <-chan struct{}
	once    sync.Once
}

func (f *recordingFilter) Match(_ context.Context, event *nostr.Event, meta map[string]any) (kitpolicy.FilterResult, error) {
	f.mu.Lock()
	f.metas = append(f.metas, meta)
	match := f.match
	started := f.started
	block := f.block
	f.mu.Unlock()

	if started != nil {
		f.once.Do(func() { close(started) })
	}
	if block != nil {
		<-block
	}
	if match != nil {
		return match(event)
	}
	return kitpolicy.FilterResult{Allowed: true, Filter: "RecordingFilter"}, nil
}

func (f *recordingFilter) Close() error {
	f.closed.Add(1)
	return nil
}

func (f *recordingFilter) lastMeta() map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.metas) == 0 {
		return nil
	}
	return f.metas[len(f.metas)-1]
}

type recordingHandler struct {
	mu      sync.Mutex
	handled int
	closed  atomic.Int32
}

func (h *recordingHandler) HandleRejection(context.Context, *nostr.Event, string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.handled++
}

func (h *recordingHandler) Close() error {
	h.closed.Add(1)
	return nil
}

func (h *recordingHandler) handledCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.handled
}

func TestPipelineClosesStagesAndHandlers(t *testing.T) {
	filter := &recordingFilter{}
	handler := &recordingHandler{}
	pipeline := NewPipeline(&config.Config{}, []kitpolicy.Filter{filter}, []RejectionHandler{handler})

	if err := pipeline.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := filter.closed.Load(); got != 1 {
		t.Fatalf("filter Close calls = %d, want 1", got)
	}
	if got := handler.closed.Load(); got != 1 {
		t.Fatalf("rejection handler Close calls = %d, want 1", got)
	}

	// Close must be idempotent; components must not be closed twice.
	if err := pipeline.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if got := filter.closed.Load(); got != 1 {
		t.Fatalf("filter Close calls after second Close = %d, want 1", got)
	}
	if got := handler.closed.Load(); got != 1 {
		t.Fatalf("rejection handler Close calls after second Close = %d, want 1", got)
	}
}

func TestPipelineRejectsEventsAfterClose(t *testing.T) {
	filter := &recordingFilter{}
	pipeline := NewPipeline(&config.Config{}, []kitpolicy.Filter{filter}, nil)
	if err := pipeline.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	eventID := nostr.ID{1}
	result, err := pipeline.ProcessEvent(context.Background(), &nostr.Event{ID: eventID}, "", false)
	if err == nil {
		t.Fatal("ProcessEvent returned no error after Close")
	}
	if result.ID != eventID.Hex() || result.Action != "reject" {
		t.Fatalf("response = %+v, want a reject for after-close", result)
	}
}

func TestPipelineExposesDryRunMetadata(t *testing.T) {
	filter := &recordingFilter{}
	pipeline := NewPipeline(&config.Config{}, []kitpolicy.Filter{filter}, nil)
	defer pipeline.Close()

	event := &nostr.Event{ID: nostr.ID{2}}
	if _, err := pipeline.ProcessEvent(context.Background(), event, "", true); err != nil {
		t.Fatalf("ProcessEvent: %v", err)
	}
	if got := filter.lastMeta()["dry_run"]; got != true {
		t.Fatalf("meta[dry_run] = %v, want true", got)
	}

	if _, err := pipeline.ProcessEvent(context.Background(), event, "", false); err != nil {
		t.Fatalf("ProcessEvent: %v", err)
	}
	if got := filter.lastMeta()["dry_run"]; got != false {
		t.Fatalf("meta[dry_run] = %v, want false", got)
	}
}

func TestPipelineDryRunAcceptsWithoutHandlers(t *testing.T) {
	filter := &recordingFilter{match: func(*nostr.Event) (kitpolicy.FilterResult, error) {
		return kitpolicy.FilterResult{Allowed: false, Filter: "RecordingFilter", Reason: "denied"}, nil
	}}
	handler := &recordingHandler{}
	pipeline := NewPipeline(&config.Config{}, []kitpolicy.Filter{filter}, []RejectionHandler{handler})
	defer pipeline.Close()

	result, err := pipeline.ProcessEvent(context.Background(), &nostr.Event{ID: nostr.ID{3}}, "", true)
	if err != nil {
		t.Fatalf("ProcessEvent: %v", err)
	}
	if result.Action != "accept" {
		t.Fatalf("dry-run action = %q, want accept", result.Action)
	}
	if handler.handledCount() != 0 {
		t.Fatal("dry-run invoked rejection handlers")
	}
}

func TestPipelineRunsHandlersOnRejection(t *testing.T) {
	filter := &recordingFilter{match: func(*nostr.Event) (kitpolicy.FilterResult, error) {
		return kitpolicy.FilterResult{Allowed: false, Filter: "RecordingFilter", Reason: "denied"}, nil
	}}
	handler := &recordingHandler{}
	pipeline := NewPipeline(&config.Config{}, []kitpolicy.Filter{filter}, []RejectionHandler{handler})
	defer pipeline.Close()

	result, err := pipeline.ProcessEvent(context.Background(), &nostr.Event{ID: nostr.ID{4}}, "", false)
	if err != nil {
		t.Fatalf("ProcessEvent: %v", err)
	}
	if result.Action != "reject" || result.Msg != "denied" {
		t.Fatalf("response = %+v, want reject with filter reason", result)
	}
	if handler.handledCount() != 1 {
		t.Fatalf("handler calls = %d, want 1", handler.handledCount())
	}
}

func TestPipelineFilterErrorRejectsWithoutHandlers(t *testing.T) {
	filterErr := errors.New("storage unavailable")
	filter := &recordingFilter{match: func(*nostr.Event) (kitpolicy.FilterResult, error) {
		return kitpolicy.FilterResult{Filter: "RecordingFilter"}, filterErr
	}}
	handler := &recordingHandler{}
	pipeline := NewPipeline(&config.Config{}, []kitpolicy.Filter{filter}, []RejectionHandler{handler})
	defer pipeline.Close()

	result, err := pipeline.ProcessEvent(context.Background(), &nostr.Event{ID: nostr.ID{5}}, "", false)
	if !errors.Is(err, filterErr) {
		t.Fatalf("error = %v, want %v", err, filterErr)
	}
	if result.Action != "reject" {
		t.Fatalf("action = %q, want reject", result.Action)
	}
	if handler.handledCount() != 0 {
		t.Fatal("operational filter failure counted as a rejection")
	}
}

func TestPipelineRecoversFilterPanic(t *testing.T) {
	filter := &recordingFilter{match: func(*nostr.Event) (kitpolicy.FilterResult, error) {
		panic("boom")
	}}
	pipeline := NewPipeline(&config.Config{}, []kitpolicy.Filter{filter}, nil)
	defer pipeline.Close()

	result, err := pipeline.ProcessEvent(context.Background(), &nostr.Event{ID: nostr.ID{6}}, "", false)
	if err != nil {
		t.Fatalf("ProcessEvent returned an error after a recovered panic: %v", err)
	}
	if result.Action != "reject" {
		t.Fatalf("action = %q, want reject", result.Action)
	}
}

func TestPipelineCloseWaitsForInFlightEvent(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	filter := &recordingFilter{started: started, block: release}
	pipeline := NewPipeline(&config.Config{}, []kitpolicy.Filter{filter}, nil)

	eventDone := make(chan PolicyResponse, 1)
	go func() {
		result, _ := pipeline.ProcessEvent(context.Background(), &nostr.Event{ID: nostr.ID{7}}, "", false)
		eventDone <- result
	}()

	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("event did not reach the filter")
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- pipeline.Close() }()
	select {
	case err := <-closeDone:
		t.Fatalf("Close returned %v while an event was still being processed", err)
	case <-time.After(100 * time.Millisecond):
	}

	close(release)
	select {
	case <-closeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not return after the in-flight event finished")
	}
	select {
	case result := <-eventDone:
		if result.Action != "accept" {
			t.Fatalf("in-flight action = %q, want accept", result.Action)
		}
	case <-time.After(time.Second):
		t.Fatal("in-flight ProcessEvent did not return")
	}
}
