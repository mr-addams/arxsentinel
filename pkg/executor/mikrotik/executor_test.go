// ========================== Package mikrotik — tests ==========================
//   Unit tests for MikroTikExecutor: ban, safe unban, TTL conversion,
//   min-level filtering, and registration.

package mikrotik

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mr-addams/arxsentinel/pkg/executor"
	"github.com/mr-addams/arx-core/pkg/logger"
	"github.com/mr-addams/arx-core/pkg/plugin"
)

// ++++++++++++++++++++++++++ Test helpers +++++++++++++++++++++++++++++++++++++

// testMikroTik creates a fresh executor backed by an httptest server.
// The handler is responsible for all REST endpoints the test needs.
func testMikroTik(t *testing.T, handler http.HandlerFunc, ttl time.Duration, minLevel string) (*httptest.Server, *MikroTikExecutor) {
	t.Helper()
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)

	exec := &MikroTikExecutor{
		name: "test",
		cfg: Config{
			ListName:   "test_list",
			SentinelID: "test",
			TTL:        ttl,
			MinLevel:   minLevel,
		},
		client: &HTTPClient{
			baseURL:    ts.URL + "/rest",
			httpClient: ts.Client(),
		},
		banned: make(map[string]banRecord),
		logger: logger.Nop,
	}
	return ts, exec
}

// ++++++++++++++++++++++++++ TestBanAddsEntry ++++++++++++++++++++++++++++++++++
func TestBanAddsEntry(t *testing.T) {
	var requestBody string

	_, exec := testMikroTik(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Write([]byte("[]"))
		case http.MethodPut:
			b, _ := io.ReadAll(r.Body)
			requestBody = string(b)
			w.Write([]byte(`{"id":"*1"}`))
		}
	}), 1*time.Hour, "THREAT")

	if err := exec.syncExisting(context.Background()); err != nil {
		t.Fatalf("syncExisting: %v", err)
	}

	exec.flush(context.Background(), []plugin.ThreatEvent{
		{IP: "1.2.3.4", Level: "THREAT"},
	})

	var entry AddressListEntry
	if err := json.Unmarshal([]byte(requestBody), &entry); err != nil {
		t.Fatalf("unmarshal PUT body: %v", err)
	}
	if entry.Address != "1.2.3.4" {
		t.Errorf("expected address 1.2.3.4, got %q", entry.Address)
	}
	if entry.Comment != "sentinel-test" {
		t.Errorf("expected comment sentinel-test, got %q", entry.Comment)
	}
	if entry.Timeout == "" {
		t.Error("expected non-empty timeout")
	}
}

// ++++++++++++++++++++++++++ TestSafeUnban +++++++++++++++++++++++++++++++++++++
func TestSafeUnban(t *testing.T) {
	var deletedIDs []string

	_, exec := testMikroTik(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			w.Write([]byte(`[
				{".id":"*1","address":"1.2.3.4","list":"test_list","comment":"sentinel-test","timeout":"1h"},
				{".id":"*2","address":"5.6.7.8","list":"test_list","comment":"other","timeout":"1h"}
			]`))
		case http.MethodDelete:
			id := strings.TrimPrefix(r.URL.Path, "/rest/ip/firewall/address-list/")
			deletedIDs = append(deletedIDs, id)
			w.WriteHeader(http.StatusOK)
		}
	}), 10*time.Millisecond, "THREAT")

	if err := exec.syncExisting(context.Background()); err != nil {
		t.Fatalf("syncExisting: %v", err)
	}

	exec.mu.Lock()
	_, hasSentinel := exec.banned["1.2.3.4"]
	_, hasOther := exec.banned["5.6.7.8"]
	exec.mu.Unlock()

	if !hasSentinel {
		t.Error("expected 1.2.3.4 to be synced (sentinel comment)")
	}
	if hasOther {
		t.Error("expected 5.6.7.8 NOT to be synced (other comment)")
	}

	time.Sleep(20 * time.Millisecond)

	exec.sweep(context.Background())

	if len(deletedIDs) != 1 {
		t.Fatalf("expected 1 DELETE, got %d: %v", len(deletedIDs), deletedIDs)
	}
	if deletedIDs[0] != "*1" {
		t.Errorf("expected DELETE of *1, got %q", deletedIDs[0])
	}
}

// ++++++++++++++++++++++++++ TestDurationToRouterOS +++++++++++++++++++++++++++
func TestDurationToRouterOS(t *testing.T) {
	tests := []struct {
		name     string
		input    time.Duration
		expected string
	}{
		{"25 hours", 25 * time.Hour, "1d1h"},
		{"90 minutes", 90 * time.Minute, "1h30m"},
		{"30 seconds", 30 * time.Second, "30s"},
		{"zero (permanent)", 0, ""},
		{"7 days", 7 * 24 * time.Hour, "7d"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := durationToRouterOS(tc.input)
			if got != tc.expected {
				t.Errorf("durationToRouterOS(%v) = %q, want %q", tc.input, got, tc.expected)
			}
		})
	}
}

// ++++++++++++++++++++++++++ TestMinLevelFilter +++++++++++++++++++++++++++++++
func TestMinLevelFilter(t *testing.T) {
	_, exec := testMikroTik(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("[]"))
	}), 1*time.Hour, "THREAT")

	if err := exec.syncExisting(context.Background()); err != nil {
		t.Fatalf("syncExisting: %v", err)
	}

	if exec.meetsMinLevel("INFO") {
		t.Error("INFO should not meet THREAT min_level")
	}
	if exec.meetsMinLevel("WARN") {
		t.Error("WARN should not meet THREAT min_level")
	}
	if !exec.meetsMinLevel("THREAT") {
		t.Error("THREAT should meet THREAT min_level")
	}
	if exec.meetsMinLevel("UNKNOWN") {
		t.Error("UNKNOWN level should never meet any min_level")
	}

	before := exec.stats.skipped.Load()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	exec.Run(ctx, &testEventSource{ //nolint:errcheck
		events: []plugin.ThreatEvent{
			{IP: "1.2.3.4", Level: "WARN"},
		},
	})
	after := exec.stats.skipped.Load()
	if after-before != 1 {
		t.Errorf("expected 1 skipped event, got %d", after-before)
	}
}

// ++++++++++++++++++++++++++ TestRegistration +++++++++++++++++++++++++++++++++
func TestMikroTikRegistration(t *testing.T) {
	found := false
	for _, name := range executor.Names() {
		if name == "mikrotik" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected 'mikrotik' in executor.Names(), not found")
	}
}

// testEventSource is a simple EventSource that delivers pre-defined events.
type testEventSource struct {
	events []plugin.ThreatEvent
	idx    int
}

func (s *testEventSource) Pop(ctx context.Context) (plugin.ThreatEvent, error) {
	if s.idx >= len(s.events) {
		<-ctx.Done()
		return plugin.ThreatEvent{}, ctx.Err()
	}
	ev := s.events[s.idx]
	s.idx++
	return ev, nil
}
