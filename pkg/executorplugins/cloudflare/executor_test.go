// ========================== pkg/executor/cloudflare — executor_test.go ======
//   Tests for CloudflareExecutor: rule management, API calls, error handling.
//
//   Gate B (Flow 083 / Task 3.3): ThreatEvent lives in
//   internal/threat; tests construct *threat.ThreatEvent values for the
//   Event.Payload.

package cloudflare

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mr-addams/arx-core/pkg/plugin"

	"github.com/mr-addams/arxsentinel/internal/threat"
)

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

func (m *mockCFClient) AddItem(_ context.Context, _, ip, _ string) (string, error) {
	m.added = append(m.added, ip)
	return "item-" + ip, m.addErr
}

func (m *mockCFClient) GetAllItems(_ context.Context, _ string) ([]CFItem, error) {
	return m.items, nil
}

func (m *mockCFClient) AddItems(_ context.Context, _ string, items []CFBatchItem) (string, error) {
	for _, item := range items {
		m.added = append(m.added, item.IP)
	}
	return "op-add", m.addErr
}

func (m *mockCFClient) RemoveItems(_ context.Context, _ string, ids []string) (string, error) {
	m.removed = append(m.removed, ids...)
	return "op-remove", m.removeErr
}

func (m *mockCFClient) PollBulkOperation(_ context.Context, _ string) (string, error) {
	return "completed", nil
}

func newTestExecutor(client CFClient, cfg Config) *CloudflareExecutor {
	return &CloudflareExecutor{
		name:       "test",
		cfg:        cfg,
		client:     client,
		listID:     "test-list-id",
		banned:     make(map[string]banRecord),
		instanceID: "test-instance",
	}
}

func TestRun_SingleItem(t *testing.T) {
	mock := new(mockCFClient)
	cfg := DefaultConfig()
	cfg.MinLevel = "INFO"
	ex := newTestExecutor(mock, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	src := newTestEventSource([]*plugin.Event{
		{Payload: &threat.ThreatEvent{IP: "1.2.3.4", Level: "THREAT"}},
		{Payload: &threat.ThreatEvent{IP: "5.6.7.8", Level: "THREAT"}},
		{Payload: &threat.ThreatEvent{IP: "1.2.3.4", Level: "THREAT"}},
	})
	_ = ex.Run(ctx, src)

	if len(mock.added) != 2 {
		t.Errorf("expected 2 AddItems calls, got %d", len(mock.added))
	}
}

func TestRun_Batch250(t *testing.T) {
	mock := new(mockCFClient)
	cfg := DefaultConfig()
	cfg.BatchSize = 100
	cfg.MinLevel = "INFO"
	ex := newTestExecutor(mock, cfg)

	events := make([]*plugin.Event, 250)
	for i := 0; i < 250; i++ {
		events[i] = &plugin.Event{Payload: &threat.ThreatEvent{IP: fmt.Sprintf("10.0.0.%d", i), Level: "THREAT"}}
	}
	_ = ex.Run(context.Background(), newTestEventSource(events))
	if len(mock.added) != 250 {
		t.Errorf("expected 250 items added, got %d", len(mock.added))
	}
}

func TestRun_LevelGate(t *testing.T) {
	mock := new(mockCFClient)
	cfg := DefaultConfig()
	cfg.MinLevel = "THREAT"
	ex := newTestExecutor(mock, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	src := newTestEventSource([]*plugin.Event{
		{Payload: &threat.ThreatEvent{IP: "10.0.0.1", Level: "INFO"}},
		{Payload: &threat.ThreatEvent{IP: "10.0.0.2", Level: "THREAT"}},
	})
	_ = ex.Run(ctx, src)

	if len(mock.added) != 1 {
		t.Errorf("expected 1 AddItems call, got %d", len(mock.added))
	}
	stats := ex.Stats()
	if stats.Skipped != 1 {
		t.Errorf("expected Skipped=1, got %d", stats.Skipped)
	}
}

func TestRun_Dedup(t *testing.T) {
	mock := new(mockCFClient)
	cfg := DefaultConfig()
	cfg.MinLevel = "INFO"
	ex := newTestExecutor(mock, cfg)

	ex.mu.Lock()
	ex.banned["10.0.0.1"] = banRecord{addedAt: time.Now()}
	ex.mu.Unlock()

	src := newTestEventSource([]*plugin.Event{
		{Payload: &threat.ThreatEvent{IP: "10.0.0.1", Level: "THREAT"}},
		{Payload: &threat.ThreatEvent{IP: "10.0.0.2", Level: "THREAT"}},
	})
	_ = ex.Run(context.Background(), src)

	if len(mock.added) != 1 {
		t.Errorf("expected 1 AddItems call (dedup), got %d", len(mock.added))
	}
}

func TestSweepExpired(t *testing.T) {
	mock := new(mockCFClient)
	cfg := DefaultConfig()
	cfg.TTL = 1 * time.Hour
	ex := newTestExecutor(mock, cfg)

	ex.mu.Lock()
	for i := 0; i < 5; i++ {
		ip := fmt.Sprintf("10.0.0.%d", i)
		ex.banned[ip] = banRecord{
			cfItemID: fmt.Sprintf("id-%d", i),
			addedAt:  time.Now().Add(-2 * time.Hour),
		}
	}
	ex.mu.Unlock()

	ex.sweep(context.Background())

	if len(mock.removed) != 5 {
		t.Errorf("expected 5 removals, got %d", len(mock.removed))
	}
	if len(ex.banned) != 0 {
		t.Errorf("expected 0 banned items after sweep, got %d", len(ex.banned))
	}
}

func TestSweepNonExpired(t *testing.T) {
	mock := new(mockCFClient)
	cfg := DefaultConfig()
	cfg.TTL = 1 * time.Hour
	ex := newTestExecutor(mock, cfg)

	ex.mu.Lock()
	ex.banned["10.0.0.1"] = banRecord{cfItemID: "id-1", addedAt: time.Now()}
	ex.mu.Unlock()

	ex.sweep(context.Background())

	if len(mock.removed) != 0 {
		t.Errorf("expected 0 removals for non-expired, got %d", len(mock.removed))
	}
}

func TestBuildComment_WithInstanceID(t *testing.T) {
	ex := &CloudflareExecutor{instanceID: "abc-123"}
	if got := ex.buildComment(); got != "sentinel-abc-123" {
		t.Errorf("expected sentinel-abc-123, got %s", got)
	}
}

func TestBuildComment_WithExtra(t *testing.T) {
	ex := &CloudflareExecutor{
		instanceID: "abc-123",
		cfg:        Config{CommentExtra: "prod-eu"},
	}
	if got := ex.buildComment(); got != "sentinel-abc-123 prod-eu" {
		t.Errorf("expected 'sentinel-abc-123 prod-eu', got %s", got)
	}
}

func TestBuildComment_ExtraTruncated(t *testing.T) {
	long := strings.Repeat("x", 60)
	ex := &CloudflareExecutor{
		instanceID: "abc-123",
		cfg:        Config{CommentExtra: long},
	}
	got := ex.buildComment()
	if !strings.HasPrefix(got, "sentinel-abc-123 ") {
		t.Errorf("expected prefix 'sentinel-abc-123 ', got %s", got)
	}
}

func TestLoadInstanceID_FromConfig(t *testing.T) {
	cfg := &Config{InstanceID: "cfg-id"}
	if got := LoadInstanceID(cfg); got != "cfg-id" {
		t.Errorf("expected cfg-id, got %s", got)
	}
}

func TestStats(t *testing.T) {
	ex := newTestExecutor(new(mockCFClient), DefaultConfig())
	ex.stats.executed.Add(10)
	ex.stats.skipped.Add(3)
	ex.stats.errors.Add(1)

	s := ex.Stats()
	if s.Executed != 10 {
		t.Errorf("expected Executed=10, got %d", s.Executed)
	}
	if s.Skipped != 3 {
		t.Errorf("expected Skipped=3, got %d", s.Skipped)
	}
	if s.Errors != 1 {
		t.Errorf("expected Errors=1, got %d", s.Errors)
	}
}

func TestRun_ConcurrentSafe(t *testing.T) {
	mock := new(mockCFClient)
	cfg := DefaultConfig()
	cfg.BatchSize = 50
	cfg.MinLevel = "INFO"
	ex := newTestExecutor(mock, cfg)

	ctx := context.Background()
	events := make([]*plugin.Event, 100)
	for i := 0; i < 100; i++ {
		events[i] = &plugin.Event{Payload: &threat.ThreatEvent{IP: fmt.Sprintf("10.0.0.%d", i), Level: "THREAT"}}
	}
	src := newTestEventSource(events)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = ex.Run(ctx, src)
	}()
	wg.Wait()

	if len(mock.added) != 100 {
		t.Errorf("expected 100 items, got %d", len(mock.added))
	}
}

type mockCFClientWithPoll struct {
	mockCFClient
	pollCalls  int
	pollStatus []string
}

func (m *mockCFClientWithPoll) PollBulkOperation(_ context.Context, _ string) (string, error) {
	if m.pollCalls < len(m.pollStatus) {
		s := m.pollStatus[m.pollCalls]
		m.pollCalls++
		return s, nil
	}
	return "completed", nil
}

func TestFlush_PollsPendingThenCompleted(t *testing.T) {
	mock := &mockCFClientWithPoll{pollStatus: []string{"pending", "completed"}}
	cfg := DefaultConfig()
	cfg.MinLevel = "INFO"
	ex := newTestExecutor(mock, cfg)

	ex.pendingOpID = "op-prev"

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ex.flush(ctx, []threat.ThreatEvent{{IP: "1.2.3.4", Level: "THREAT"}})

	if mock.pollCalls < 2 {
		t.Errorf("expected at least 2 poll calls, got %d", mock.pollCalls)
	}
	if len(mock.added) != 1 {
		t.Errorf("expected 1 item added after poll, got %d", len(mock.added))
	}
}

type mockCFClientWith429 struct {
	mockCFClient
	addCalls  int
	failUntil int
}

func (m *mockCFClientWith429) AddItems(ctx context.Context, listID string, items []CFBatchItem) (string, error) {
	m.addCalls++
	if m.addCalls <= m.failUntil {
		return "", fmt.Errorf("cloudflare: 429 too many requests")
	}
	for _, item := range items {
		m.added = append(m.added, item.IP)
	}
	return "op-ok", nil
}

func TestFlush_429Retry(t *testing.T) {
	mock := &mockCFClientWith429{failUntil: 2}
	cfg := DefaultConfig()
	cfg.MinLevel = "INFO"
	ex := newTestExecutor(mock, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ex.flush(ctx, []threat.ThreatEvent{{IP: "1.2.3.4", Level: "THREAT"}})

	if mock.addCalls != 3 {
		t.Errorf("expected 3 AddItems calls (2 fail + 1 success), got %d", mock.addCalls)
	}
	if len(mock.added) != 1 {
		t.Errorf("expected 1 item added, got %d", len(mock.added))
	}
}

// testEventSource is a minimal plugin.EventSource for tests.
// Phase 2.2 (Flow 083 / Gate A): queue.Queue still operates on opaque bytes
// (see pkg/executor/queue/queue.go). This helper exists so tests can hand
// the executor an EventSource directly while queue.EventSource adapter
// lives in Task 3.3 (Flow 083 RESOLVED-D).
//
// On exhaustion, Pop returns io.EOF (not blocking on ctx.Done()) so Run can
// flush any buffered batch and return cleanly even under context.Background().
// Required by TestRun_Batch250 and TestRun_ConcurrentSafe, which cannot rely
// on a ctx deadline to break Pop's wait.
type testEventSource struct {
	events []*plugin.Event
	idx    int
}

func newTestEventSource(events []*plugin.Event) *testEventSource {
	return &testEventSource{events: events}
}

func (s *testEventSource) Pop(_ context.Context) (*plugin.Event, error) {
	if s.idx >= len(s.events) {
		return nil, io.EOF
	}
	ev := s.events[s.idx]
	s.idx++
	return ev, nil
}
