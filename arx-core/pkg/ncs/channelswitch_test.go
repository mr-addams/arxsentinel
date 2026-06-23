// ========================== pkg/ncs — channelswitch_test.go ===============
//   Tests for NamedSwitch: named queue registration, lookup, lifecycle.
//
//   Gate B (Flow 083 / Task 3.3 / RESOLVED-D): queue payloads are opaque
//   []byte; tests marshal a local jsonFields fixture before Push. Core
//   tests do not import the product threat.ThreatEvent (boundary invariant).

package ncs_test

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mr-addams/arx-core/pkg/executor/queue"
	"github.com/mr-addams/arx-core/pkg/logger"
	"github.com/mr-addams/arx-core/pkg/ncs"
)

// jsonFields mirrors the wire-format fixture product-side Formatter impls
// produce; tests marshal to []byte before Push.
type jsonFields struct {
	IP    string `json:"ip"`
	Level string `json:"level"`
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("test fixture marshal: %v", err)
	}
	return b
}

func TestNamedSwitch_SendReceive(t *testing.T) {
	ctx := context.Background()
	q, err := ncs.AttachWriter("test-sr", 10)
	if err != nil {
		t.Fatalf("AttachWriter error = %v, want nil", err)
	}

	src, err := ncs.AttachReader("test-sr")
	if err != nil {
		t.Fatalf("AttachReader error = %v, want nil", err)
	}

	payload := mustMarshal(t, jsonFields{IP: "1.2.3.4", Level: "THREAT"})
	if err := q.Push(ctx, payload); err != nil {
		t.Fatalf("Push error = %v, want nil", err)
	}

	got, err := src.Pop(ctx)
	if err != nil {
		t.Fatalf("Pop error = %v, want nil", err)
	}
	var decoded jsonFields
	if err := json.Unmarshal(got, &decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.IP != "1.2.3.4" {
		t.Errorf("received IP = %q, want %q", decoded.IP, "1.2.3.4")
	}
	if decoded.Level != "THREAT" {
		t.Errorf("received Level = %q, want %q", decoded.Level, "THREAT")
	}

	ncs.DetachWriter("test-sr")
}

func TestNamedSwitch_DuplicateName(t *testing.T) {
	ctx := context.Background()

	// Fan-in: two streams register the same name and get the same queue.
	q1, err := ncs.AttachWriter("test-dup", 5)
	if err != nil {
		t.Fatalf("first AttachWriter error = %v, want nil", err)
	}
	q2, err := ncs.AttachWriter("test-dup", 5)
	if err != nil {
		t.Fatalf("second AttachWriter error = %v, want nil", err)
	}
	if q1 != q2 {
		t.Error("both AttachWriter calls must return the same queue")
	}

	// Both push through different handles; consumer sees all events.
	src, _ := ncs.AttachReader("test-dup")
	_ = q1.Push(ctx, mustMarshal(t, jsonFields{IP: "1.1.1.1", Level: "THREAT"}))
	_ = q2.Push(ctx, mustMarshal(t, jsonFields{IP: "2.2.2.2", Level: "THREAT"}))

	got1, _ := src.Pop(ctx)
	got2, _ := src.Pop(ctx)
	var d1, d2 jsonFields
	_ = json.Unmarshal(got1, &d1)
	_ = json.Unmarshal(got2, &d2)
	ips := map[string]bool{d1.IP: true, d2.IP: true}
	if !ips["1.1.1.1"] || !ips["2.2.2.2"] {
		t.Errorf("expected both IPs from fan-in, got %q and %q", d1.IP, d2.IP)
	}

	// Ref count: first DetachWriter keeps queue alive.
	ncs.DetachWriter("test-dup") // ref: 2 → 1, queue must stay open
	if _, err := ncs.AttachReader("test-dup"); err != nil {
		t.Error("queue should still be open after first DetachWriter")
	}
	ncs.DetachWriter("test-dup") // ref: 1 → 0, queue closed
	if _, err := ncs.AttachReader("test-dup"); err == nil {
		t.Error("queue should be gone after last DetachWriter")
	}
}

func TestNamedSwitch_Unregister(t *testing.T) {
	ctx := context.Background()
	q, err := ncs.AttachWriter("test-unreg", 3)
	if err != nil {
		t.Fatalf("AttachWriter error = %v, want nil", err)
	}

	src, err := ncs.AttachReader("test-unreg")
	if err != nil {
		t.Fatalf("AttachReader error = %v, want nil", err)
	}

	_ = q.Push(ctx, mustMarshal(t, jsonFields{IP: "1.2.3.4", Level: "THREAT"}))
	ncs.DetachWriter("test-unreg")

	// After DetachWriter the queue is closed, but a buffered event may still be in the channel.
	// The first Pop drains the buffer (err=nil, returns the event).
	// The second Pop must return ErrQueueClosed — the channel is empty and closed.
	_, _ = src.Pop(ctx)
	_, err = src.Pop(ctx)
	if err == nil {
		t.Error("expected ErrQueueClosed on second Pop after DetachWriter, got nil")
	}
}

func TestNamedSwitch_GetSourceNotFound(t *testing.T) {
	_, err := ncs.AttachReader("nonexistent")
	if err == nil {
		t.Fatal("AttachReader(nonexistent) expected error, got nil")
	}
}

// --------------------- RegisterSinkFromConfig: branch table ---------------------
//
// Each test uses a unique queue name (t.Name()) to avoid clashes with the
// global NamedChannelSwitch singleton under parallel execution.
// DetachWriter is mandatory after every test — otherwise the queue leaks into the NCS map.

// TestRegisterSinkFromConfig_NilCfg — cfg == nil → default MemoryQueue,
// function behaves identically to AttachWriter(name, 0).
func TestRegisterSinkFromConfig_NilCfg(t *testing.T) {
	name := t.Name()

	err := ncs.RegisterSinkFromConfig(name, nil, logger.Nop)
	if err != nil {
		t.Fatalf("RegisterSinkFromConfig(nil) error = %v, want nil", err)
	}

	// Queue is registered; AttachReader must find it.
	src, err := ncs.AttachReader(name)
	if err != nil {
		t.Fatalf("AttachReader(%q) error = %v, want nil", name, err)
	}
	if src == nil {
		t.Fatal("AttachReader returned nil queue")
	}

	// The queue is functional: Push → Pop returns the same event.
	ctx := context.Background()
	payload := mustMarshal(t, jsonFields{IP: "10.0.0.1", Level: "THREAT"})
	if err := src.Push(ctx, payload); err != nil {
		t.Fatalf("Push error = %v, want nil", err)
	}
	got, err := src.Pop(ctx)
	if err != nil {
		t.Fatalf("Pop error = %v, want nil", err)
	}
	var decoded jsonFields
	_ = json.Unmarshal(got, &decoded)
	if decoded.IP != "10.0.0.1" {
		t.Errorf("Pop IP = %q, want %q", decoded.IP, "10.0.0.1")
	}

	ncs.DetachWriter(name)
}

// TestRegisterSinkFromConfig_TypeMemory — explicit type=memory → MemoryQueue.
func TestRegisterSinkFromConfig_TypeMemory(t *testing.T) {
	name := t.Name()
	cfg := &queue.QueueConfig{Type: queue.QueueTypeMemory}

	err := ncs.RegisterSinkFromConfig(name, cfg, logger.Nop)
	if err != nil {
		t.Fatalf("RegisterSinkFromConfig(memory) error = %v, want nil", err)
	}

	src, err := ncs.AttachReader(name)
	if err != nil {
		t.Fatalf("AttachReader(%q) error = %v, want nil", name, err)
	}
	if src == nil {
		t.Fatal("AttachReader returned nil queue")
	}

	// Extra check: confirm that the registered queue is the in-memory variant —
	// Push → Pop in the same process, without any serialization.
	ctx := context.Background()
	payload := mustMarshal(t, jsonFields{IP: "10.0.0.2", Level: "THREAT"})
	if err := src.Push(ctx, payload); err != nil {
		t.Fatalf("Push error = %v, want nil", err)
	}
	got, err := src.Pop(ctx)
	if err != nil {
		t.Fatalf("Pop error = %v, want nil", err)
	}
	var decoded jsonFields
	_ = json.Unmarshal(got, &decoded)
	if decoded.IP != "10.0.0.2" {
		t.Errorf("Pop IP = %q, want %q", decoded.IP, "10.0.0.2")
	}

	ncs.DetachWriter(name)
}

// TestRegisterSinkFromConfig_TypeBbolt — type=bbolt with a valid path → BboltQueue
// is registered without error. We use t.TempDir() for automatic cleanup.
func TestRegisterSinkFromConfig_TypeBbolt(t *testing.T) {
	name := t.Name()
	dbPath := filepath.Join(t.TempDir(), "queue.db")
	cfg := &queue.QueueConfig{Type: queue.QueueTypeBbolt, Path: dbPath}

	err := ncs.RegisterSinkFromConfig(name, cfg, logger.Nop)
	if err != nil {
		t.Fatalf("RegisterSinkFromConfig(bbolt) error = %v, want nil", err)
	}

	// BboltQueue is registered in NCS; AttachReader finds it.
	src, err := ncs.AttachReader(name)
	if err != nil {
		t.Fatalf("AttachReader(%q) error = %v, want nil", name, err)
	}
	if src == nil {
		t.Fatal("AttachReader returned nil queue")
	}

	// IMPORTANT: BboltQueue.DetachWriter will close it BEFORE BboltQueue finishes
	// the background writeLoop. After Close, a subsequent Push returns ErrQueueClosed —
	// that is what we assert below to confirm the NCS entry is actually a BboltQueue.
	ctx := context.Background()
	payload := mustMarshal(t, jsonFields{IP: "10.0.0.3", Level: "THREAT"})
	if err := src.Push(ctx, payload); err != nil {
		t.Fatalf("Push error = %v, want nil", err)
	}

	ncs.DetachWriter(name)
}

// TestRegisterSinkFromConfig_TypeRedis_InvalidURL — type=redis with an invalid URL
// → NewRedisQueue returns an error (redis.ParseURL cannot parse it),
// RegisterSinkFromConfig propagates it; nothing is stored in NCS.
func TestRegisterSinkFromConfig_TypeRedis_InvalidURL(t *testing.T) {
	name := t.Name()
	cfg := &queue.QueueConfig{
		Type: queue.QueueTypeRedis,
		URL:  "not-a-valid-redis-url", // redis.ParseURL expects the redis:// scheme
	}

	err := ncs.RegisterSinkFromConfig(name, cfg, logger.Nop)
	if err == nil {
		t.Fatal("RegisterSinkFromConfig(redis, bad url) expected error, got nil")
	}
	// The error message must include the sink name for log diagnostics.
	if !strings.Contains(err.Error(), name) {
		t.Errorf("error %q should mention sink name %q", err.Error(), name)
	}
	if !strings.Contains(err.Error(), "redis") {
		t.Errorf("error %q should mention redis backend", err.Error())
	}

	// Nothing is registered in NCS — AttachReader must return an error.
	_, err = ncs.AttachReader(name)
	if err == nil {
		t.Fatal("AttachReader after failed register expected error, got nil")
	}
}

// TestRegisterSinkFromConfig_UnknownType — type with an unsupported value
// → returns an error; NCS stays empty.
func TestRegisterSinkFromConfig_UnknownType(t *testing.T) {
	name := t.Name()
	cfg := &queue.QueueConfig{Type: queue.QueueType("kafka")}

	err := ncs.RegisterSinkFromConfig(name, cfg, logger.Nop)
	if err == nil {
		t.Fatal("RegisterSinkFromConfig(unknown) expected error, got nil")
	}
	if !strings.Contains(err.Error(), "kafka") {
		t.Errorf("error %q should mention the unknown type value", err.Error())
	}
	if !strings.Contains(err.Error(), name) {
		t.Errorf("error %q should mention sink name %q", err.Error(), name)
	}

	// NCS must not contain anything under this name.
	_, err = ncs.AttachReader(name)
	if err == nil {
		t.Fatal("AttachReader after unknown-type error expected error, got nil")
	}
}