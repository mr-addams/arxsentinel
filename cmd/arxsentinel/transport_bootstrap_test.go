package main

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/mr-addams/arx-core/pkg/executor/queue"
	"github.com/mr-addams/arx-core/pkg/ncs"
	"github.com/mr-addams/arx-core/pkg/transportbridge"
	"github.com/mr-addams/arxsentinel/internal/sys/config"
)

// ----------------------------------------------------------------------------------------
// Test 1: disabled transport is a no-op — no SetDefault call, no tracked goroutine.
// ----------------------------------------------------------------------------------------
func TestStartTransport_DisabledIsNoOp(t *testing.T) {
	transportbridge.SetDefault(nil) // isolate from any other test's global state
	defer transportbridge.SetDefault(nil)

	cfg := &config.Config{Transport: config.TransportConfig{Enabled: false}}
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := startTransport(ctx, cfg, &wg); err != nil {
		t.Fatalf("startTransport(disabled) = %v, want nil", err)
	}

	if _, err := transportbridge.GetDefault(); err == nil {
		t.Error("transportbridge.GetDefault() = nil error after disabled startTransport, want ErrNotConfigured")
	}

	// wg must have zero pending goroutines — Wait() must return immediately.
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("wg.Wait() did not return — disabled startTransport tracked an unexpected goroutine")
	}
}

// ----------------------------------------------------------------------------------------
// Test 2: enabled transport registers itself via transportbridge and its Run
// goroutine is tracked by the caller's WaitGroup (exits cleanly on ctx cancel).
// ----------------------------------------------------------------------------------------
func TestStartTransport_EnabledSetsDefaultAndTracksGoroutine(t *testing.T) {
	transportbridge.SetDefault(nil)
	defer transportbridge.SetDefault(nil)

	dir := t.TempDir()
	cfg := &config.Config{Transport: config.TransportConfig{
		Enabled:        true,
		IdentityPath:   filepath.Join(dir, "node.key"),
		KnownNodesPath: filepath.Join(dir, "known-nodes"),
		Listen:         "127.0.0.1:0",
	}}
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())

	if err := startTransport(ctx, cfg, &wg); err != nil {
		t.Fatalf("startTransport(enabled) = %v, want nil", err)
	}

	if _, err := transportbridge.GetDefault(); err != nil {
		t.Errorf("transportbridge.GetDefault() = %v, want a live Transport", err)
	}

	// Cancelling ctx must let Run() return and wg.Wait() unblock.
	cancel()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("wg.Wait() did not return after ctx cancel — transport goroutine leaked")
	}
}

// ----------------------------------------------------------------------------------------
// Test 3: sentinelQueueName mirrors pkg/source/sentinel's addr parsing contract.
// ----------------------------------------------------------------------------------------
func TestSentinelQueueName(t *testing.T) {
	cases := []struct {
		name    string
		addr    string
		want    string
		wantErr bool
	}{
		{"valid", "ncs://edge-raw", "edge-raw", false},
		{"missing scheme", "edge-raw", "", true},
		{"wrong scheme", "http://edge-raw", "", true},
		{"empty name", "ncs://", "", true},
		{"empty addr", "", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := sentinelQueueName(tc.addr)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("sentinelQueueName(%q) = nil error, want error", tc.addr)
				}
				return
			}
			if err != nil {
				t.Fatalf("sentinelQueueName(%q) = %v, want nil error", tc.addr, err)
			}
			if got != tc.want {
				t.Errorf("sentinelQueueName(%q) = %q, want %q", tc.addr, got, tc.want)
			}
		})
	}
}

// ----------------------------------------------------------------------------------------
// Test 4: preRegisterSinkQueues skips outputs without queue: (legacy path) and
// non-sentinel-threat outputs untouched, without error.
// ----------------------------------------------------------------------------------------
func TestPreRegisterSinkQueues_SkipsWithoutQueue(t *testing.T) {
	cfg := &config.Config{
		Outputs: []config.SinkConfig{
			{Type: "file", Path: "/dev/null"},
			{Type: "sentinel-threat", Name: "no-queue-here"}, // Queue == nil
		},
	}
	if err := preRegisterSinkQueues(cfg); err != nil {
		t.Fatalf("preRegisterSinkQueues = %v, want nil", err)
	}
}

// ----------------------------------------------------------------------------------------
// Test 5: preRegisterSinkQueues rejects a sentinel-threat output that sets
// queue: but omits the required name field — nothing to register under.
// ----------------------------------------------------------------------------------------
func TestPreRegisterSinkQueues_MissingNameErrors(t *testing.T) {
	cfg := &config.Config{
		Outputs: []config.SinkConfig{
			{Type: "sentinel-threat", Queue: &queue.QueueConfig{Type: queue.QueueTypeMemory}},
		},
	}
	if err := preRegisterSinkQueues(cfg); err == nil {
		t.Fatal("preRegisterSinkQueues = nil error, want error for missing name")
	}
}

// ----------------------------------------------------------------------------------------
// Test 6: preRegisterSinkQueues registers a memory-backed queue.Type under the
// output's Name, discoverable afterwards via ncs.AttachReader.
// ----------------------------------------------------------------------------------------
func TestPreRegisterSinkQueues_RegistersMemoryQueue(t *testing.T) {
	const name = "test-preregister-sink-memory"
	defer ncs.DetachWriter(name)

	cfg := &config.Config{
		Streams: []config.StreamConfig{{
			Outputs: []config.SinkConfig{
				{Type: "sentinel-threat", Name: name, Queue: &queue.QueueConfig{Type: queue.QueueTypeMemory}},
			},
		}},
	}
	if err := preRegisterSinkQueues(cfg); err != nil {
		t.Fatalf("preRegisterSinkQueues = %v, want nil", err)
	}
	if _, err := ncs.AttachReader(name); err != nil {
		t.Errorf("ncs.AttachReader(%q) = %v, want a registered queue", name, err)
	}
}

// ----------------------------------------------------------------------------------------
// Test 7: preRegisterInboundTransportQueues skips "sentinel" inputs without
// queue: and non-"sentinel" input types, without error.
// ----------------------------------------------------------------------------------------
func TestPreRegisterInboundTransportQueues_SkipsWithoutQueue(t *testing.T) {
	cfg := &config.Config{
		Inputs: []config.InputConfig{
			{Type: "file", Path: "/dev/null"},
			{Type: "sentinel", Addr: "ncs://no-queue-here"}, // Queue == nil
		},
	}
	if err := preRegisterInboundTransportQueues(cfg); err != nil {
		t.Fatalf("preRegisterInboundTransportQueues = %v, want nil", err)
	}
}

// ----------------------------------------------------------------------------------------
// Test 8: preRegisterInboundTransportQueues registers a memory-backed queue
// under the name parsed from Addr, discoverable via ncs.AttachReader.
// ----------------------------------------------------------------------------------------
func TestPreRegisterInboundTransportQueues_RegistersMemoryQueue(t *testing.T) {
	const name = "test-preregister-inbound-memory"
	defer ncs.DetachWriter(name)

	cfg := &config.Config{
		Streams: []config.StreamConfig{{
			Pipelines: []config.PipelineConfig{{
				Inputs: []config.InputConfig{
					{Type: "sentinel", Addr: "ncs://" + name, Queue: &queue.QueueConfig{Type: queue.QueueTypeMemory}},
				},
			}},
		}},
	}
	if err := preRegisterInboundTransportQueues(cfg); err != nil {
		t.Fatalf("preRegisterInboundTransportQueues = %v, want nil", err)
	}
	if _, err := ncs.AttachReader(name); err != nil {
		t.Errorf("ncs.AttachReader(%q) = %v, want a registered queue", name, err)
	}
}

// ----------------------------------------------------------------------------------------
// Test 9: preRegisterInboundTransportQueues rejects a malformed Addr on a
// "sentinel" input that sets queue: — the name cannot be derived.
// ----------------------------------------------------------------------------------------
func TestPreRegisterInboundTransportQueues_BadAddrErrors(t *testing.T) {
	cfg := &config.Config{
		Inputs: []config.InputConfig{
			{Type: "sentinel", Addr: "not-an-ncs-addr", Queue: &queue.QueueConfig{Type: queue.QueueTypeMemory}},
		},
	}
	if err := preRegisterInboundTransportQueues(cfg); err == nil {
		t.Fatal("preRegisterInboundTransportQueues = nil error, want error for malformed addr")
	}
}
