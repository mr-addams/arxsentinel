// ========================== Package cloudflare ==========================
//   Tests for CloudflareExecutor — uses a mock CFClient to verify
//   Execute and sweep logic without real HTTP calls.

package cloudflare

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/mr-addams/arxsentinel/pkg/plugin"
)

// ========================== Mock CFClient ==========================

// mockCFClient implements CFClient for unit tests.
// It records all AddItem and RemoveItems calls for assertions.
type mockCFClient struct {
	listID    string
	items     []CFItem
	addErr    error
	removeErr error
	added     []string
	removed   []string
}

func (m *mockCFClient) FindOrCreateList(_ context.Context, _ string) (string, error) {
	return m.listID, nil
}

func (m *mockCFClient) ListItems(_ context.Context, _ string) ([]CFItem, error) {
	return m.items, nil
}

// AddItem returns a synthetic item ID to satisfy the updated CFClient
// interface (S-02). The ID is derived from the IP for test traceability.
func (m *mockCFClient) AddItem(_ context.Context, _, ip, _ string) (string, error) {
	m.added = append(m.added, ip)
	id := "item-" + ip
	return id, m.addErr
}

func (m *mockCFClient) GetAllItems(_ context.Context, _ string) ([]CFItem, error) {
	return m.items, nil
}

func (m *mockCFClient) AddItems(_ context.Context, _ string, items []CFBatchItem) error {
	for _, item := range items {
		m.added = append(m.added, item.IP)
	}
	return m.addErr
}

func (m *mockCFClient) RemoveItems(_ context.Context, _ string, ids []string) error {
	m.removed = append(m.removed, ids...)
	return m.removeErr
}

// ========================== Test helpers ==========================

// newTestExecutor creates a CloudflareExecutor with a mock client.
// No sweep goroutine is started — stopSweep is a no-op so Close()
// can be called without panic.
func newTestExecutor(client CFClient, cfg Config) *CloudflareExecutor {
	return &CloudflareExecutor{
		name:      "test",
		cfg:       cfg,
		client:    client,
		listID:    "test-list-id",
		banned:    make(map[string]banRecord),
		deduped:   make(map[string]time.Time),
		stopSweep: func() {}, // no-op; Close() won't panic if called
	}
}

// ========================== Tests ==========================

// ++++++++++++++++++++++++++ TestExecute_LevelGate ++++++++++++++++++++++++++

// TestExecute_LevelGate verifies that events below MinLevel are skipped
// without calling the CF API.
func TestExecute_LevelGate(t *testing.T) {
	mock := &mockCFClient{listID: "test-list-id"}
	exec := newTestExecutor(mock, Config{MinLevel: "THREAT"})

	event := plugin.ThreatEvent{
		IP:        "10.0.0.1",
		Level:     "INFO",
		Timestamp: time.Now(),
	}

	if err := exec.Execute(context.Background(), event); err != nil {
		t.Fatalf("Execute returned unexpected error: %v", err)
	}

	stats := exec.Stats()
	if stats.Skipped != 1 {
		t.Errorf("expected Skipped=1 after level gate, got %d", stats.Skipped)
	}
	if stats.Executed != 0 {
		t.Errorf("expected Executed=0 after level gate, got %d", stats.Executed)
	}
	if len(mock.added) != 0 {
		t.Errorf("expected AddItem not to be called, called %d time(s)", len(mock.added))
	}
}

// ++++++++++++++++++++++++++ TestExecute_Dedup ++++++++++++++++++++++++++

// TestExecute_Dedup verifies that two identical IP events result in only
// one AddItem call; the second is skipped as a duplicate.
func TestExecute_Dedup(t *testing.T) {
	mock := &mockCFClient{listID: "test-list-id"}
	exec := newTestExecutor(mock, Config{MinLevel: "INFO"})

	event := plugin.ThreatEvent{
		IP:        "10.0.0.1",
		Level:     "THREAT",
		Timestamp: time.Now(),
	}

	// First call — should succeed
	if err := exec.Execute(context.Background(), event); err != nil {
		t.Fatalf("first Execute returned unexpected error: %v", err)
	}

	// Second call with same IP — should be skipped as duplicate
	if err := exec.Execute(context.Background(), event); err != nil {
		t.Fatalf("second Execute returned unexpected error: %v", err)
	}

	stats := exec.Stats()
	if stats.Executed != 1 {
		t.Errorf("expected Executed=1, got %d", stats.Executed)
	}
	if stats.Skipped != 1 {
		t.Errorf("expected Skipped=1 for duplicate, got %d", stats.Skipped)
	}
	if len(mock.added) != 1 {
		t.Errorf("expected 1 AddItem call, got %d", len(mock.added))
	}
	if len(mock.added) > 0 && mock.added[0] != "10.0.0.1" {
		t.Errorf("expected AddItem called with 10.0.0.1, got %s", mock.added[0])
	}
}

// ++++++++++++++++++++++++++ TestExecute_MaxItems ++++++++++++++++++++++++++

// TestExecute_MaxItems verifies that when MaxItems is set, events beyond
// the limit are skipped.
func TestExecute_MaxItems(t *testing.T) {
	mock := &mockCFClient{listID: "test-list-id"}
	exec := newTestExecutor(mock, Config{MinLevel: "INFO", MaxItems: 1})

	// First IP — should succeed (banned count < MaxItems)
	event1 := plugin.ThreatEvent{
		IP:        "10.0.0.1",
		Level:     "THREAT",
		Timestamp: time.Now(),
	}
	if err := exec.Execute(context.Background(), event1); err != nil {
		t.Fatalf("first Execute returned unexpected error: %v", err)
	}

	// Second IP — should be skipped (banned count >= MaxItems)
	event2 := plugin.ThreatEvent{
		IP:        "10.0.0.2",
		Level:     "THREAT",
		Timestamp: time.Now(),
	}
	if err := exec.Execute(context.Background(), event2); err != nil {
		t.Fatalf("second Execute returned unexpected error: %v", err)
	}

	stats := exec.Stats()
	if stats.Executed != 1 {
		t.Errorf("expected Executed=1, got %d", stats.Executed)
	}
	if stats.Skipped != 1 {
		t.Errorf("expected Skipped=1 for exceeding MaxItems, got %d", stats.Skipped)
	}
	if len(mock.added) != 1 {
		t.Errorf("expected 1 AddItem call, got %d", len(mock.added))
	}
}

// ++++++++++++++++++++++++++ TestExecute_Success ++++++++++++++++++++++++++

// TestExecute_Success verifies a successful AddItem call increments
// the executed counter and the IP is stored in the banned map.
func TestExecute_Success(t *testing.T) {
	mock := &mockCFClient{listID: "test-list-id"}
	exec := newTestExecutor(mock, Config{MinLevel: "INFO"})

	event := plugin.ThreatEvent{
		IP:        "10.0.0.1",
		Level:     "THREAT",
		Timestamp: time.Now(),
		Reason:    "test:rate>100",
	}

	if err := exec.Execute(context.Background(), event); err != nil {
		t.Fatalf("Execute returned unexpected error: %v", err)
	}

	stats := exec.Stats()
	if stats.Executed != 1 {
		t.Errorf("expected Executed=1, got %d", stats.Executed)
	}
	if stats.Skipped != 0 {
		t.Errorf("expected Skipped=0, got %d", stats.Skipped)
	}

	// Verify the IP is in the banned map with addedByExecutor=true
	if !exec.isBanned("10.0.0.1") {
		t.Fatal("expected IP 10.0.0.1 to be in banned map")
	}
	exec.mu.Lock()
	rec := exec.banned["10.0.0.1"]
	exec.mu.Unlock()
	if rec.addedByExecutor != true {
		t.Error("expected addedByExecutor to be true")
	}
}

// ++++++++++++++++++++++++++ TestExecute_Concurrent ++++++++++++++++++++++++

// TestExecute_Concurrent verifies that multiple goroutines can call Execute
// concurrently with different IPs without data races.
func TestExecute_Concurrent(t *testing.T) {
	mock := &mockCFClient{listID: "test-list-id"}
	exec := newTestExecutor(mock, Config{MinLevel: "INFO"})

	var wg sync.WaitGroup
	const numGoroutines = 10

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			event := plugin.ThreatEvent{
				IP:        fmt.Sprintf("10.0.0.%d", idx+1),
				Level:     "THREAT",
				Timestamp: time.Now(),
			}
			if err := exec.Execute(context.Background(), event); err != nil {
				t.Errorf("Execute returned error: %v", err)
			}
		}(i)
	}

	wg.Wait()

	stats := exec.Stats()
	if stats.Executed != int64(numGoroutines) {
		t.Errorf("expected Executed=%d, got %d", numGoroutines, stats.Executed)
	}
	if stats.Errors != 0 {
		t.Errorf("expected Errors=0, got %d", stats.Errors)
	}
}

// ++++++++++++++++++++++++++ TestSweepExpired ++++++++++++++++++++++++++

// TestSweepExpired verifies that sweepOnce removes expired bans from
// the Cloudflare list and the local banned map.
func TestSweepExpired(t *testing.T) {
	mock := &mockCFClient{listID: "test-list-id"}
	cfg := Config{TTL: 1 * time.Hour}
	exec := newTestExecutor(mock, cfg)

	// Insert an expired record (addedAt = now - 2*TTL) with cfItemID set
	exec.mu.Lock()
	exec.banned["10.0.0.1"] = banRecord{
		cfItemID: "item-1",
		addedAt:  time.Now().Add(-2 * time.Hour),
	}
	exec.mu.Unlock()

	exec.sweepOnce(context.Background())

	// Verify RemoveItems was called with the expired cfItemID
	if len(mock.removed) != 1 {
		t.Fatalf("expected 1 removal, got %d", len(mock.removed))
	}
	if mock.removed[0] != "item-1" {
		t.Errorf("expected RemoveItems called with item-1, got %s", mock.removed[0])
	}

	// Verify the IP was removed from the local banned map
	if exec.isBanned("10.0.0.1") {
		t.Error("expected IP 10.0.0.1 to be removed from banned after sweep")
	}
}

// ++++++++++++++++++++++++++ TestExecute_RollbackOnError ++++++++++++++++++++++

// TestExecute_RollbackOnError verifies that when AddItem fails, the
// pre-registered IP is removed from the banned map and the error counter
// is incremented.
func TestExecute_RollbackOnError(t *testing.T) {
	mock := &mockCFClient{
		listID: "test-list-id",
		addErr: errors.New("api error"),
	}
	exec := newTestExecutor(mock, Config{MinLevel: "INFO"})

	event := plugin.ThreatEvent{
		IP:        "10.0.0.1",
		Level:     "THREAT",
		Timestamp: time.Now(),
	}

	err := exec.Execute(context.Background(), event)
	if err == nil {
		t.Fatal("expected error from Execute when AddItem fails")
	}

	stats := exec.Stats()
	if stats.Executed != 0 {
		t.Errorf("expected Executed=0 after failed AddItem, got %d", stats.Executed)
	}
	if stats.Errors != 1 {
		t.Errorf("expected Errors=1 after failed AddItem, got %d", stats.Errors)
	}

	// Verify rollback — IP must NOT be in banned after failure
	if exec.isBanned("10.0.0.1") {
		t.Error("expected IP 10.0.0.1 to be removed from banned after failed AddItem (rollback)")
	}
}

// ++++++++++++++++++++++++++ TestExecute_DedupWindow ++++++++++++++++++++++++++++

// TestExecute_DedupWindow verifies that DedupWindow blocks re-execution within
// the window, but allows execution after the window expires.
func TestExecute_DedupWindow(t *testing.T) {
	mock := &mockCFClient{listID: "test-list-id"}
	exec := newTestExecutor(mock, Config{
		MinLevel:    "INFO",
		DedupWindow: 1 * time.Hour,
	})
	// Manually set a fake dedup time in the future for an IP.
	exec.mu.Lock()
	exec.deduped["10.0.0.1"] = time.Now().Add(1 * time.Hour)
	exec.mu.Unlock()

	event := plugin.ThreatEvent{
		IP:        "10.0.0.1",
		Level:     "THREAT",
		Timestamp: time.Now(),
	}

	// First call — should be skipped because deduped is active
	if err := exec.Execute(context.Background(), event); err != nil {
		t.Fatalf("Execute returned unexpected error: %v", err)
	}
	stats := exec.Stats()
	if stats.Skipped != 1 {
		t.Errorf("expected Skipped=1 (dedup window), got %d", stats.Skipped)
	}
	if len(mock.added) != 0 {
		t.Errorf("expected 0 AddItem calls (dedup window), got %d", len(mock.added))
	}
}

// TestExecute_DedupWindowExpired verifies that when DedupWindow has expired,
// a new ban is allowed.
func TestExecute_DedupWindowExpired(t *testing.T) {
	mock := &mockCFClient{listID: "test-list-id"}
	exec := newTestExecutor(mock, Config{
		MinLevel:    "INFO",
		DedupWindow: 1 * time.Hour,
	})
	// Set dedup time in the past — should be treated as expired.
	exec.mu.Lock()
	exec.deduped["10.0.0.1"] = time.Now().Add(-1 * time.Minute)
	exec.mu.Unlock()

	event := plugin.ThreatEvent{
		IP:        "10.0.0.1",
		Level:     "THREAT",
		Timestamp: time.Now(),
	}

	if err := exec.Execute(context.Background(), event); err != nil {
		t.Fatalf("Execute returned unexpected error: %v", err)
	}
	stats := exec.Stats()
	if stats.Executed != 1 {
		t.Errorf("expected Executed=1 (dedup window expired), got %d", stats.Executed)
	}
	if len(mock.added) != 1 {
		t.Errorf("expected 1 AddItem call (dedup window expired), got %d", len(mock.added))
	}
}
