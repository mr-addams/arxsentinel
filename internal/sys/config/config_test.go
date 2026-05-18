// ========================== Tests for config module ========================================
//   Verifies LoadConfig: defaults, YAML overrides, Duration parsing.
//
//   Test configs are complete (all section fields) — due to yaml.v3 partial merge limitation.
//   Sections absent from YAML retain Go defaults.

package config

import (
	"os"
	"strings"
	"testing"
	"time"
)

// ========================== Test: defaults without a file ====================================

func TestLoadConfig_Defaults(t *testing.T) {
	// Non-existent path → LoadConfig must return defaults without an error.
	// This allows the daemon to start out of the box without config.yaml.
	cfg, err := LoadConfig("/nonexistent/path/nginx-sentinel-test-config.yaml")
	if err != nil {
		t.Fatalf("non-existent config must return defaults without error, got: %v", err)
	}

	// ── Scoring ───────────────────────────────────────────────────────────────────────

	if cfg.Scoring.AlertThreshold != 50 {
		t.Errorf("Scoring.AlertThreshold: want 50, got %d", cfg.Scoring.AlertThreshold)
	}
	if cfg.Scoring.BanThreshold != 80 {
		t.Errorf("Scoring.BanThreshold: want 80, got %d", cfg.Scoring.BanThreshold)
	}
	if time.Duration(cfg.Scoring.ObservationWindow) != 300*time.Second {
		t.Errorf("Scoring.ObservationWindow: want 300s, got %v", time.Duration(cfg.Scoring.ObservationWindow))
	}
	if cfg.Scoring.Decay != "linear" {
		t.Errorf("Scoring.Decay: want linear, got %q", cfg.Scoring.Decay)
	}

	// ── State ─────────────────────────────────────────────────────────────────────────

	if time.Duration(cfg.State.GCInterval) != 60*time.Second {
		t.Errorf("State.GCInterval: want 60s, got %v", time.Duration(cfg.State.GCInterval))
	}
	if cfg.State.MaxTrackedIPs != 100000 {
		t.Errorf("State.MaxTrackedIPs: want 100000, got %d", cfg.State.MaxTrackedIPs)
	}

	// ── Detectors ─────────────────────────────────────────────────────────────────────

	if !cfg.Detectors.Probe.Enabled {
		t.Error("Detectors.Probe.Enabled: want true")
	}
	if cfg.Detectors.Probe.Score != 25 {
		t.Errorf("Detectors.Probe.Score: want 25, got %d", cfg.Detectors.Probe.Score)
	}
	if len(cfg.Detectors.Probe.Paths) == 0 {
		t.Error("Detectors.Probe.Paths: want non-empty list")
	}
	if !cfg.Detectors.Bruteforce.Enabled {
		t.Error("Detectors.Bruteforce.Enabled: want true")
	}
	if cfg.Detectors.Rate.Threshold != 100 {
		t.Errorf("Detectors.Rate.Threshold: want 100, got %d", cfg.Detectors.Rate.Threshold)
	}
	if cfg.Detectors.UserAgent.ScannerScore != 40 {
		t.Errorf("Detectors.UserAgent.ScannerScore: want 40, got %d", cfg.Detectors.UserAgent.ScannerScore)
	}
	if cfg.Detectors.UserAgent.EmptyUAScore != 30 {
		t.Errorf("Detectors.UserAgent.EmptyUAScore: want 30, got %d", cfg.Detectors.UserAgent.EmptyUAScore)
	}

	// ── Whitelist ─────────────────────────────────────────────────────────────────────

	if len(cfg.Whitelist.Bots) == 0 {
		t.Error("Whitelist.Bots: want non-empty list")
	}
	if time.Duration(cfg.Whitelist.DNSCache.PositiveTTL) != 24*time.Hour {
		t.Errorf("DNSCache.PositiveTTL: want 24h, got %v", time.Duration(cfg.Whitelist.DNSCache.PositiveTTL))
	}
	if time.Duration(cfg.Whitelist.DNSCache.NegativeTTL) != time.Hour {
		t.Errorf("DNSCache.NegativeTTL: want 1h, got %v", time.Duration(cfg.Whitelist.DNSCache.NegativeTTL))
	}

	// ── Logging ───────────────────────────────────────────────────────────────────────

	if cfg.Logging.Debug {
		t.Error("Logging.Debug: want false")
	}
	if !cfg.Logging.ConsoleColor {
		t.Error("Logging.ConsoleColor: want true")
	}
}

// ========================== Test: YAML overrides ==============================

func TestLoadConfig_Override(t *testing.T) {
	// YAML contains full sections for scoring and logging — partial sections are not tested
	// due to yaml.v3 limitation (partial section zeroes unmentioned fields).
	// Sections state and detectors are absent from YAML → must retain defaults.
	content := `
scoring:
  alert_threshold: 60
  ban_threshold: 90
  observation_window: "10m"
  decay: "linear"
logging:
  debug: true
  console_color: false
`
	f := writeTempYAML(t, content)
	defer os.Remove(f)

	cfg, err := LoadConfig(f)
	if err != nil {
		t.Fatalf("LoadConfig error: %v", err)
	}

	// ── Overridden values ─────────────────────────────────────────────────────

	if cfg.Scoring.AlertThreshold != 60 {
		t.Errorf("Scoring.AlertThreshold: want 60, got %d", cfg.Scoring.AlertThreshold)
	}
	if cfg.Scoring.BanThreshold != 90 {
		t.Errorf("Scoring.BanThreshold: want 90, got %d", cfg.Scoring.BanThreshold)
	}
	if time.Duration(cfg.Scoring.ObservationWindow) != 10*time.Minute {
		t.Errorf("Scoring.ObservationWindow: want 10m, got %v", time.Duration(cfg.Scoring.ObservationWindow))
	}
	if !cfg.Logging.Debug {
		t.Error("Logging.Debug: want true")
	}
	if cfg.Logging.ConsoleColor {
		t.Error("Logging.ConsoleColor: want false")
	}

	// ── Sections without YAML → retain defaults ──────────────────────────────────────────

	if cfg.State.MaxTrackedIPs != 100000 {
		t.Errorf("State.MaxTrackedIPs: want 100000 (default), got %d", cfg.State.MaxTrackedIPs)
	}
	if !cfg.Detectors.Probe.Enabled {
		t.Error("Detectors.Probe.Enabled: want true (default)")
	}
	if len(cfg.Whitelist.Bots) == 0 {
		t.Error("Whitelist.Bots: want non-empty (default)")
	}
}

// ========================== Test: Duration from YAML =====================================

func TestLoadConfig_Duration(t *testing.T) {
	content := `
state:
  gc_interval: "2m"
  max_tracked_ips: 50000
detectors:
  rate:
    enabled: true
    window: "30s"
    threshold: 100
    score: 25
whitelist:
  dns_cache:
    positive_ttl: "48h"
    negative_ttl: "30m"
    ip_list_refresh: "12h"
`
	f := writeTempYAML(t, content)
	defer os.Remove(f)

	cfg, err := LoadConfig(f)
	if err != nil {
		t.Fatalf("LoadConfig error: %v", err)
	}

	cases := []struct {
		name string
		got  time.Duration
		want time.Duration
	}{
		{"State.GCInterval", time.Duration(cfg.State.GCInterval), 2 * time.Minute},
		{"Rate.Window", time.Duration(cfg.Detectors.Rate.Window), 30 * time.Second},
		{"DNSCache.PositiveTTL", time.Duration(cfg.Whitelist.DNSCache.PositiveTTL), 48 * time.Hour},
		{"DNSCache.NegativeTTL", time.Duration(cfg.Whitelist.DNSCache.NegativeTTL), 30 * time.Minute},
		{"DNSCache.IPListRefresh", time.Duration(cfg.Whitelist.DNSCache.IPListRefresh), 12 * time.Hour},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s: want %v, got %v", c.name, c.want, c.got)
		}
	}
}

// ========================== Test: invalid YAML ======================================

func TestLoadConfig_InvalidYAML(t *testing.T) {
	f := writeTempYAML(t, "{ invalid yaml: [unclosed")
	defer os.Remove(f)

	_, err := LoadConfig(f)
	if err == nil {
		t.Error("invalid YAML must return an error")
	}
}

// ========================== Test: correctness of default bots ==========================

func TestLoadConfig_DefaultBots(t *testing.T) {
	cfg, err := LoadConfig("/nonexistent")
	if err != nil {
		t.Fatalf("LoadConfig with non-existent file must return defaults without error: %v", err)
	}

	// Verify that the key bots are present
	found := map[string]bool{}
	for _, b := range cfg.Whitelist.Bots {
		found[b.Name] = true
	}

	required := []string{"google", "bing", "yandex", "gptbot", "claudebot"}
	for _, name := range required {
		if !found[name] {
			t.Errorf("Whitelist.Bots: bot %q not found in defaults", name)
		}
	}

	// Google must use rdns_ipjson verification
	for _, b := range cfg.Whitelist.Bots {
		if b.Name == "google" {
			if b.VerifyMethod != "rdns_ipjson" {
				t.Errorf("google.VerifyMethod: want rdns_ipjson, got %q", b.VerifyMethod)
			}
			if len(b.UAPatterns) == 0 {
				t.Error("google.UAPatterns: want non-empty")
			}
		}
	}
}

// ========================== Test: stderr on missing config ========================

func TestLoadConfig_StderrOnMissingFile(t *testing.T) {
	// On ENOENT LoadConfig must write a message to stderr —
	// the operator must know the daemon is running on defaults, not their config.yaml.

	// Capture os.Stderr via pipe
	origStderr := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stderr = w

	LoadConfig("/nonexistent/path/nginx-sentinel-test-stderr.yaml")

	w.Close()
	os.Stderr = origStderr

	buf := make([]byte, 512)
	n, _ := r.Read(buf)
	output := string(buf[:n])

	if !strings.Contains(output, "not found, using defaults") {
		t.Errorf("stderr must contain 'not found, using defaults', got: %q", output)
	}
}

// ========================== Tests: regex parser config ================================

func TestLoadConfig_RegexParser(t *testing.T) {
	pattern := `(?P<remote_addr>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<request>[^"]+)" (?P<status>\d+) (?P<bytes_sent>\d+)`
	path := writeTempYAML(t, `
parser:
  log_format: "regex"
  regex_pattern: '`+pattern+`'
general:
  log_file: /var/log/nginx/access.log
output:
  threat_log: /var/log/nginx-sentinel/threats.log
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Parser.LogFormat != "regex" {
		t.Errorf("LogFormat: want %q, got %q", "regex", cfg.Parser.LogFormat)
	}
	if cfg.Parser.RegexPattern != pattern {
		t.Errorf("RegexPattern: want %q, got %q", pattern, cfg.Parser.RegexPattern)
	}
}

func TestLoadConfig_RegexPattern_DefaultEmpty(t *testing.T) {
	// Default config must have empty regex_pattern — no pattern pre-filled.
	cfg, _ := LoadConfig("/nonexistent/defaults-only.yaml")
	if cfg.Parser.RegexPattern != "" {
		t.Errorf("RegexPattern default: want empty, got %q", cfg.Parser.RegexPattern)
	}
}

// ========================== Tests: profile config =====================================

func TestLoadConfig_Profile(t *testing.T) {
	path := writeTempYAML(t, `
parser:
  profile: "apache"
general:
  log_file: /var/log/apache2/access.log
output:
  threat_log: /var/log/nginx-sentinel/threats.log
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Parser.Profile != "apache" {
		t.Errorf("Parser.Profile: want %q, got %q", "apache", cfg.Parser.Profile)
	}
}

func TestLoadConfig_ProfileDefault(t *testing.T) {
	// Default config must have empty profile — no profile pre-filled.
	cfg, _ := LoadConfig("/nonexistent/defaults-only.yaml")
	if cfg.Parser.Profile != "" {
		t.Errorf("Parser.Profile default: want empty, got %q", cfg.Parser.Profile)
	}
}

// ========================== Tests: multi-stream config ================================

func TestLoadConfig_BackwardCompat_SingleStream(t *testing.T) {
	// Classic general.log_file must be converted to a single unnamed stream.
	path := writeTempYAML(t, `
general:
  log_file: /var/log/nginx/access.log
output:
  threat_log: /var/log/nginx-sentinel/threats.log
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(cfg.Streams) != 1 {
		t.Fatalf("Streams: want 1, got %d", len(cfg.Streams))
	}
	s := cfg.Streams[0]
	if s.Name != "" {
		t.Errorf("Streams[0].Name: want empty string, got %q", s.Name)
	}
	if s.LogFile != "/var/log/nginx/access.log" {
		t.Errorf("Streams[0].LogFile: want %q, got %q", "/var/log/nginx/access.log", s.LogFile)
	}
	if s.ThreatLog != "/var/log/nginx-sentinel/threats.log" {
		t.Errorf("Streams[0].ThreatLog: want %q, got %q", "/var/log/nginx-sentinel/threats.log", s.ThreatLog)
	}
}

func TestLoadConfig_MultiStream(t *testing.T) {
	// Explicit streams: block must produce one StreamConfig per entry.
	path := writeTempYAML(t, `
streams:
  - name: site1
    log_file: /var/log/nginx/site1.access.log
    threat_log: /var/log/nginx-sentinel/site1.threats.log
  - name: site2
    log_file: /var/log/nginx/site2.access.log
    threat_log: /var/log/nginx-sentinel/site2.threats.log
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(cfg.Streams) != 2 {
		t.Fatalf("Streams: want 2, got %d", len(cfg.Streams))
	}
	if cfg.Streams[0].Name != "site1" {
		t.Errorf("Streams[0].Name: want %q, got %q", "site1", cfg.Streams[0].Name)
	}
	if cfg.Streams[1].LogFile != "/var/log/nginx/site2.access.log" {
		t.Errorf("Streams[1].LogFile: want %q, got %q",
			"/var/log/nginx/site2.access.log", cfg.Streams[1].LogFile)
	}
}

func TestLoadConfig_MutualExclusion(t *testing.T) {
	// Combining general.log_file and streams: must return an error.
	path := writeTempYAML(t, `
general:
  log_file: /var/log/nginx/access.log
streams:
  - name: site1
    log_file: /var/log/nginx/site1.access.log
    threat_log: /var/log/nginx-sentinel/site1.threats.log
output:
  threat_log: /var/log/nginx-sentinel/threats.log
`)
	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("LoadConfig: want error for combining general.log_file and streams:, got nil")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("error must mention 'mutually exclusive', got: %v", err)
	}
}

func TestLoadConfig_StreamMissingLogFile(t *testing.T) {
	// A stream without log_file must fail validation.
	path := writeTempYAML(t, `
streams:
  - name: site1
    threat_log: /var/log/nginx-sentinel/site1.threats.log
`)
	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("LoadConfig: want error for missing log_file, got nil")
	}
}

func TestLoadConfig_StreamMissingThreatLog(t *testing.T) {
	// A stream without threat_log must fail validation.
	path := writeTempYAML(t, `
streams:
  - name: site1
    log_file: /var/log/nginx/site1.access.log
`)
	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("LoadConfig: want error for missing threat_log, got nil")
	}
}

// ========================== Helper ====================================================

// writeTempYAML creates a temporary file with the given content and returns its path.
func writeTempYAML(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp("", "nginx-sentinel-test-*.yaml")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("writing to temp file: %v", err)
	}
	f.Close()
	return f.Name()
}
