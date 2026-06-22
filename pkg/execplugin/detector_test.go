// ========================== pkg/execplugin — detector_test.go ==============
//   Tests for ExecDetector: Manifest, CanHandle, lifecycle.

package execplugin

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/mr-addams/arx-core/pkg/plugin"
)

// mockIPView is a test double implementing plugin.IPView.
type mockIPView struct {
	ip            string
	totalRequests int
	requests404   int
	recentPaths   []string
	approxRate1m  float64
}

func (m *mockIPView) GetIP() string                           { return m.ip }
func (m *mockIPView) GetTotalRequests() int                   { return m.totalRequests }
func (m *mockIPView) GetRequests404() int                     { return m.requests404 }
func (m *mockIPView) RecentPaths() []string                   { return m.recentPaths }
func (m *mockIPView) ApproxRate(window time.Duration) float64 { return m.approxRate1m }

// TestExecDetector_Name tests that Name() returns the detector's registered name.
func TestExecDetector_Name(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	testdataDir := filepath.Join(filepath.Dir(filename), "testdata")
	scriptPath := filepath.Join(testdataDir, "detector.sh")

	detector, err := NewDetector("my-detector", scriptPath, nil, context.Background())
	if err != nil {
		t.Fatalf("NewDetector failed: %v", err)
	}
	defer detector.Close()

	if name := detector.Name(); name != "my-detector" {
		t.Errorf("Name() = %q, want %q", name, "my-detector")
	}
}

// TestExecDetector_Detect tests the happy path: sending a request and receiving a response.
func TestExecDetector_Detect(t *testing.T) {
	_, filename, _, _ := runtime.Caller(0)
	testdataDir := filepath.Join(filepath.Dir(filename), "testdata")
	scriptPath := filepath.Join(testdataDir, "detector.sh")

	detector, err := NewDetector("test-detector", scriptPath, nil, context.Background())
	if err != nil {
		t.Fatalf("NewDetector failed: %v", err)
	}
	defer detector.Close()

	// Create a mock IPView
	ipView := &mockIPView{
		ip:            "1.2.3.4",
		totalRequests: 10,
		requests404:   3,
		recentPaths:   []string{"/admin", "/login"},
		approxRate1m:  2.5,
	}

	// Create a test LogEntry
	logEntry := &plugin.LogEntry{
		RemoteAddr: "1.2.3.4",
		Method:     "GET",
		Path:       "/admin",
		Status:     403,
		UserAgent:  "curl/7.68.0",
	}

	// Call Detect
	result := detector.Detect(ipView, logEntry)

	// Verify the response
	if result.Score != 42 {
		t.Errorf("Score = %d, want 42", result.Score)
	}
	if result.Module != "test-detector" {
		t.Errorf("Module = %q, want %q", result.Module, "test-detector")
	}
	if result.Reason != "test:1" {
		t.Errorf("Reason = %q, want %q", result.Reason, "test:1")
	}
}

// TestExecDetector_CrashReturnsError tests that a non-existent binary fails at NewDetector.
func TestExecDetector_CrashReturnsError(t *testing.T) {
	_, err := NewDetector("broken", "/nonexistent-binary-xyz-definitely-not-found", nil, context.Background())
	if err == nil {
		t.Errorf("NewDetector with nonexistent binary should return error, got nil")
	}
}
