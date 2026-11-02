package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"fiatjaf.com/nostr"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/lessucettes/adresu-plugin/internal/config"
	"github.com/lessucettes/adresu-plugin/internal/policy"
	"github.com/lessucettes/adresu-plugin/pkg/adresu-kit/nip"
	kitpolicy "github.com/lessucettes/adresu-plugin/pkg/adresu-kit/policy"
)

type inputFilter func(*nostr.Event) (kitpolicy.FilterResult, error)

func testEventID(label string) nostr.ID { return nostr.ID(sha256.Sum256([]byte(label))) }

// These protocol-only fixtures reach a stub policy, not signature admission.
func testPolicyLine(label string) string {
	event := nostr.Event{ID: testEventID(label), PubKey: nostr.KeyOne.Public(), Sig: [64]byte{1}}
	raw, err := json.Marshal(PolicyInput{Event: event})
	if err != nil {
		panic(err)
	}
	return string(raw)
}

func (f inputFilter) Match(_ context.Context, ev *nostr.Event, _ map[string]any) (kitpolicy.FilterResult, error) {
	return f(ev)
}

func installTestPipeline(t *testing.T, filter inputFilter) {
	t.Helper()
	installTestFilter(t, filter)
}

func installTestFilter(t *testing.T, filter kitpolicy.Filter) {
	t.Helper()
	pipelineMutex.Lock()
	previous := currentPipeline
	currentPipeline = policy.NewPipeline(&config.Config{}, []kitpolicy.Filter{filter}, nil)
	pipelineMutex.Unlock()
	t.Cleanup(func() {
		pipelineMutex.Lock()
		p := currentPipeline
		currentPipeline = previous
		pipelineMutex.Unlock()
		_ = p.Close()
	})
}

func TestProcessEventsRespondsAfterFilterError(t *testing.T) {
	installTestPipeline(t, func(ev *nostr.Event) (kitpolicy.FilterResult, error) {
		if ev.ID == testEventID("failed") {
			return kitpolicy.FilterResult{Filter: "test"}, errors.New("storage unavailable")
		}
		return kitpolicy.FilterResult{Allowed: true}, nil
	})
	input := testPolicyLine("failed") + "\n" + testPolicyLine("ok") + "\n"
	var output bytes.Buffer
	if err := processEvents(context.Background(), strings.NewReader(input), &output, false); err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(&output)
	for _, want := range []policy.PolicyResponse{{ID: testEventID("failed").Hex(), Action: "reject"}, {ID: testEventID("ok").Hex(), Action: "accept"}} {
		var got policy.PolicyResponse
		if err := decoder.Decode(&got); err != nil {
			t.Fatalf("missing response for %s: %v", want.ID, err)
		}
		if got.ID != want.ID || got.Action != want.Action {
			t.Fatalf("response = %+v, want ID %q action %q", got, want.ID, want.Action)
		}
	}
}

func TestProcessEventsRejectsUndecodableEvent(t *testing.T) {
	installTestPipeline(t, func(*nostr.Event) (kitpolicy.FilterResult, error) {
		return kitpolicy.FilterResult{Allowed: true}, nil
	})
	// strfry checks only the first two tag elements. A signed event with a
	// numeric third element can reach the plugin but cannot decode into Tag.
	id := strings.Repeat("a", 64)
	input := `{"event":{"tags":[["t","value",42]],"id":"` + id + `"}}` + "\n" +
		testPolicyLine("next") + "\n"
	var output bytes.Buffer
	if err := processEvents(context.Background(), strings.NewReader(input), &output, false); err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(&output)
	for _, want := range []policy.PolicyResponse{{ID: id, Action: "reject"}, {ID: testEventID("next").Hex(), Action: "accept"}} {
		var got policy.PolicyResponse
		if err := decoder.Decode(&got); err != nil || got.ID != want.ID || got.Action != want.Action {
			t.Fatalf("response = %+v, error = %v, want %+v", got, err, want)
		}
	}
}

func TestProcessEventsContinuesAfterDecodeError(t *testing.T) {
	for _, malformed := range []string{
		`{"event":{"id":42,"tags":[["t","value",42]]}}`,
		`{"event":{"tags":[["t","value",42]]}}`,
		`{"event":`,
	} {
		t.Run(malformed, func(t *testing.T) {
			installTestPipeline(t, func(*nostr.Event) (kitpolicy.FilterResult, error) {
				return kitpolicy.FilterResult{Allowed: true}, nil
			})
			var output bytes.Buffer
			input := malformed + "\n" + testPolicyLine("next") + "\n"
			if err := processEvents(context.Background(), strings.NewReader(input), &output, false); err != nil {
				t.Fatalf("malformed request stopped processing: %v", err)
			}
			var response policy.PolicyResponse
			if err := json.Unmarshal(output.Bytes(), &response); err != nil || response.ID != testEventID("next").Hex() || response.Action != "accept" {
				t.Fatalf("output = %q, error = %v; want only the next event's response", output.String(), err)
			}
		})
	}
}

func TestProcessEventsValidatesBinaryEventFields(t *testing.T) {
	event := nostr.Event{Kind: nostr.KindReaction, CreatedAt: 1, Content: "test", Tags: nostr.Tags{}}
	if err := event.Sign(nostr.KeyOne); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(PolicyInput{Event: event, SourceType: "IP4", SourceInfo: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, field string
		value       any
	}{
		{"short_id", "id", "ab"},
		{"nonhex_id", "id", strings.Repeat("g", 64)},
		{"short_pubkey", "pubkey", "ab"},
		{"nonhex_pubkey", "pubkey", strings.Repeat("g", 64)},
		{"invalid_curve_point", "pubkey", strings.Repeat("0", 64)},
		{"short_signature", "sig", "ab"},
		{"nonhex_signature", "sig", strings.Repeat("g", 128)},
		{"null_signature", "sig", nil},
		{"wrapped_kind", "kind", 65536 + int(nostr.KindReaction)},
		{"negative_kind", "kind", -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var wire map[string]any
			if err := json.Unmarshal(raw, &wire); err != nil {
				t.Fatal(err)
			}
			fields := wire["event"].(map[string]any)
			fields[tc.field] = tc.value
			id := fields["id"].(string)
			invalid, err := json.Marshal(wire)
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			unexpected := false
			installTestPipeline(t, func(got *nostr.Event) (kitpolicy.FilterResult, error) {
				calls++
				if got.ID != event.ID || got.PubKey != event.PubKey || got.Kind != event.Kind {
					unexpected = true
				}
				return kitpolicy.FilterResult{Allowed: true}, nil
			})
			var output bytes.Buffer
			if err := processEvents(context.Background(), strings.NewReader(string(invalid)+"\n"+string(raw)+"\n"), &output, false); err != nil {
				t.Fatal(err)
			}
			decoder := json.NewDecoder(&output)
			for _, want := range []policy.PolicyResponse{{ID: id, Action: "reject"}, {ID: event.ID.Hex(), Action: "accept"}} {
				var got policy.PolicyResponse
				if err := decoder.Decode(&got); err != nil || got.ID != want.ID || got.Action != want.Action {
					t.Fatalf("response = %+v, error = %v, want %+v", got, err, want)
				}
			}
			if calls != 1 || unexpected {
				t.Fatalf("policy received %d events; malformed input must not reach it", calls)
			}
		})
	}

	t.Run("uppercase_signed_wire_identity", func(t *testing.T) {
		// strfry hashes the original pubkey string, including its hex casing.
		canonical := `[0,"` + strings.ToUpper(event.PubKey.Hex()) + `",1,7,[],"test"]`
		hash := sha256.Sum256([]byte(canonical))
		privateKey, _ := btcec.PrivKeyFromBytes(nostr.KeyOne[:])
		signature, err := schnorr.Sign(privateKey, hash[:])
		if err != nil {
			t.Fatal(err)
		}
		upperID := strings.ToUpper(hex.EncodeToString(hash[:]))
		upper := strings.ReplaceAll(string(raw), event.ID.Hex(), upperID)
		upper = strings.ReplaceAll(upper, event.PubKey.Hex(), strings.ToUpper(event.PubKey.Hex()))
		upper = strings.ReplaceAll(upper, hex.EncodeToString(event.Sig[:]), hex.EncodeToString(signature.Serialize()))
		installTestFilter(t, signatureInputFilter{})
		var output bytes.Buffer
		if err := processEvents(context.Background(), strings.NewReader(upper+"\n"), &output, false); err != nil {
			t.Fatal(err)
		}
		var got policy.PolicyResponse
		if err := json.Unmarshal(output.Bytes(), &got); err != nil || got.ID != upperID || got.Action != "accept" {
			t.Fatalf("response = %+v, error = %v; input ID spelling must be preserved", got, err)
		}
	})
}

type signatureInputFilter struct{}

func (signatureInputFilter) Match(ctx context.Context, event *nostr.Event, _ map[string]any) (kitpolicy.FilterResult, error) {
	valid, err := nip.CheckEventSignature(ctx, event)
	return kitpolicy.FilterResult{Allowed: valid && event.ID == nip.CanonicalEventID(ctx, event)}, err
}

func TestProcessEventsBoundsRejectionResponse(t *testing.T) {
	for _, tc := range []struct {
		name, reason string
		retain       bool
	}{
		{"large_pattern", strings.Repeat("long forbidden pattern ", 1000), false},
		{"json_escaping", strings.Repeat("\x00", 2000), false},
		{"within_limit", strings.Repeat("a", 2000), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			installTestPipeline(t, func(*nostr.Event) (kitpolicy.FilterResult, error) {
				return kitpolicy.FilterResult{Reason: tc.reason}, nil
			})
			var output bytes.Buffer
			if err := processEvents(context.Background(), strings.NewReader(testPolicyLine("blocked")+"\n"), &output, false); err != nil {
				t.Fatal(err)
			}
			// strfry's PluginEventSifter caps plugin output records at 8192 bytes.
			if output.Len() > 8192 {
				t.Fatalf("response is %d bytes and cannot be read by strfry", output.Len())
			}
			var response policy.PolicyResponse
			if err := json.Unmarshal(output.Bytes(), &response); err != nil || response.ID != testEventID("blocked").Hex() || response.Action != "reject" || response.Msg == "" {
				t.Fatalf("invalid rejection response: %v", err)
			}
			if tc.retain && response.Msg != tc.reason {
				t.Fatal("a reason within the record limit was changed")
			}
		})
	}
}

func TestProcessEventsLargeLineAndFinalLine(t *testing.T) {
	installTestPipeline(t, func(ev *nostr.Event) (kitpolicy.FilterResult, error) {
		return kitpolicy.FilterResult{Allowed: len(ev.Content) <= 100000}, nil
	})
	large, err := json.Marshal(PolicyInput{Event: nostr.Event{ID: testEventID("large"), PubKey: nostr.KeyOne.Public(), Sig: [64]byte{1}, Content: strings.Repeat("x", 150000)}})
	if err != nil {
		t.Fatal(err)
	}
	input := string(large) + "\n" + testPolicyLine("final")
	var output bytes.Buffer
	if err := processEvents(context.Background(), strings.NewReader(input), &output, false); err != nil {
		t.Fatalf("large input never reached the size policy: %v", err)
	}
	decoder := json.NewDecoder(&output)
	for _, want := range []policy.PolicyResponse{{ID: testEventID("large").Hex(), Action: "reject"}, {ID: testEventID("final").Hex(), Action: "accept"}} {
		var got policy.PolicyResponse
		if err := decoder.Decode(&got); err != nil || got.ID != want.ID || got.Action != want.Action {
			t.Fatalf("response = %+v, error = %v, want %+v", got, err, want)
		}
	}
}

type failingWriter struct{ err error }

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }

func TestProcessEventsReturnsOutputFailure(t *testing.T) {
	installTestPipeline(t, func(*nostr.Event) (kitpolicy.FilterResult, error) {
		return kitpolicy.FilterResult{Allowed: true}, nil
	})
	want := errors.New("output failed")
	err := processEvents(context.Background(), strings.NewReader(testPolicyLine("one")+"\n"), failingWriter{want}, false)
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
}

type observedReader struct {
	*io.PipeReader
	started chan struct{}
	once    sync.Once
}

func (r *observedReader) Read(p []byte) (int, error) {
	r.once.Do(func() { close(r.started) })
	return r.PipeReader.Read(p)
}

func TestProcessEventsCancellationClosesInput(t *testing.T) {
	r, w := io.Pipe()
	defer w.Close()
	defer r.Close()
	input := &observedReader{PipeReader: r, started: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- processEvents(ctx, input, io.Discard, false) }()
	select {
	case <-input.started:
	case <-time.After(3 * time.Second):
		t.Fatal("input read never started")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("cancellation did not stop processing")
	}
	written := make(chan error, 1)
	go func() { _, err := w.Write([]byte("x")); written <- err }()
	select {
	case err := <-written:
		if !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("input remained open: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("input reader was left blocked after cancellation")
	}
}
