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

// ========================== Tests: env var overrides =================================

func TestEnvOverride_StringAndInt(t *testing.T) {
	// String and int fields are overridden by env vars.
	t.Setenv("ARXSENTINEL_GENERAL_PID_FILE", "/tmp/test.pid")
	t.Setenv("ARXSENTINEL_SCORING_ALERT_THRESHOLD", "65")
	t.Setenv("ARXSENTINEL_SCORING_BAN_THRESHOLD", "95")
	t.Setenv("ARXSENTINEL_METRICS_LISTEN_ADDR", ":9999")

	cfg, err := LoadConfig("/nonexistent/env-override-test.yaml")
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if cfg.General.PIDFile != "/tmp/test.pid" {
		t.Errorf("PIDFile: want /tmp/test.pid, got %q", cfg.General.PIDFile)
	}
	if cfg.Scoring.AlertThreshold != 65 {
		t.Errorf("AlertThreshold: want 65, got %d", cfg.Scoring.AlertThreshold)
	}
	if cfg.Scoring.BanThreshold != 95 {
		t.Errorf("BanThreshold: want 95, got %d", cfg.Scoring.BanThreshold)
	}
	if cfg.Metrics.ListenAddr != ":9999" {
		t.Errorf("ListenAddr: want :9999, got %q", cfg.Metrics.ListenAddr)
	}
}

func TestEnvOverride_Bool(t *testing.T) {
	// Boolean env vars accept "true"/"false"/"1"/"0".
	t.Setenv("ARXSENTINEL_LOGGING_DEBUG", "true")
	t.Setenv("ARXSENTINEL_LOGGING_CONSOLE_COLOR", "0")
	t.Setenv("ARXSENTINEL_METRICS_ENABLED", "1")

	cfg, err := LoadConfig("/nonexistent/env-bool-test.yaml")
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if !cfg.Logging.Debug {
		t.Error("Logging.Debug: want true")
	}
	if cfg.Logging.ConsoleColor {
		t.Error("Logging.ConsoleColor: want false")
	}
	if !cfg.Metrics.Enabled {
		t.Error("Metrics.Enabled: want true")
	}
}

func TestEnvOverride_Duration(t *testing.T) {
	// Duration fields accept Go duration strings (e.g. "2m", "45s").
	t.Setenv("ARXSENTINEL_SCORING_OBSERVATION_WINDOW", "10m")
	t.Setenv("ARXSENTINEL_STATE_GC_INTERVAL", "45s")
	t.Setenv("ARXSENTINEL_WHITELIST_DNS_VERIFY_TIMEOUT", "5s")

	cfg, err := LoadConfig("/nonexistent/env-dur-test.yaml")
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if time.Duration(cfg.Scoring.ObservationWindow) != 10*time.Minute {
		t.Errorf("ObservationWindow: want 10m, got %v", time.Duration(cfg.Scoring.ObservationWindow))
	}
	if time.Duration(cfg.State.GCInterval) != 45*time.Second {
		t.Errorf("GCInterval: want 45s, got %v", time.Duration(cfg.State.GCInterval))
	}
	if time.Duration(cfg.Whitelist.DNSVerifyTimeout) != 5*time.Second {
		t.Errorf("DNSVerifyTimeout: want 5s, got %v", time.Duration(cfg.Whitelist.DNSVerifyTimeout))
	}
}

func TestEnvOverride_CSV(t *testing.T) {
	// Comma-separated env vars replace the corresponding slice.
	t.Setenv("ARXSENTINEL_WHITELIST_CUSTOM_IPS", "1.2.3.4, 5.6.7.8")
	t.Setenv("ARXSENTINEL_WHITELIST_CUSTOM_CIDRS", "10.0.0.0/8,192.168.0.0/16")

	cfg, err := LoadConfig("/nonexistent/env-csv-test.yaml")
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if len(cfg.Whitelist.Custom.IPs) != 2 {
		t.Fatalf("Custom.IPs: want 2 entries, got %d: %v", len(cfg.Whitelist.Custom.IPs), cfg.Whitelist.Custom.IPs)
	}
	if cfg.Whitelist.Custom.IPs[0] != "1.2.3.4" || cfg.Whitelist.Custom.IPs[1] != "5.6.7.8" {
		t.Errorf("Custom.IPs: want [1.2.3.4 5.6.7.8], got %v", cfg.Whitelist.Custom.IPs)
	}
	if len(cfg.Whitelist.Custom.CIDRs) != 2 {
		t.Fatalf("Custom.CIDRs: want 2 entries, got %d: %v", len(cfg.Whitelist.Custom.CIDRs), cfg.Whitelist.Custom.CIDRs)
	}
}

func TestEnvOverride_EmptyEnvLeavesYAMLIntact(t *testing.T) {
	// Both "not set" and "explicitly empty" env vars must leave YAML values unchanged.
	// ARXSENTINEL_SCORING_ALERT_THRESHOLD is explicitly set to "" — must not zero the field.
	t.Setenv("ARXSENTINEL_SCORING_ALERT_THRESHOLD", "")

	path := writeTempYAML(t, `
scoring:
  alert_threshold: 70
  ban_threshold: 100
  observation_window: "15m"
  decay: "linear"
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if cfg.Scoring.AlertThreshold != 70 {
		t.Errorf("AlertThreshold: want 70 (from YAML), got %d", cfg.Scoring.AlertThreshold)
	}
	if cfg.Scoring.BanThreshold != 100 {
		t.Errorf("BanThreshold: want 100 (from YAML), got %d", cfg.Scoring.BanThreshold)
	}
}

func TestEnvOverride_EnvWinsOverYAML(t *testing.T) {
	// Env vars take priority over YAML values.
	t.Setenv("ARXSENTINEL_SCORING_ALERT_THRESHOLD", "55")
	t.Setenv("ARXSENTINEL_SCORING_BAN_THRESHOLD", "88")

	path := writeTempYAML(t, `
scoring:
  alert_threshold: 70
  ban_threshold: 100
  observation_window: "15m"
  decay: "linear"
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	// Env overrides YAML.
	if cfg.Scoring.AlertThreshold != 55 {
		t.Errorf("AlertThreshold: want 55 (from env), got %d", cfg.Scoring.AlertThreshold)
	}
	if cfg.Scoring.BanThreshold != 88 {
		t.Errorf("BanThreshold: want 88 (from env), got %d", cfg.Scoring.BanThreshold)
	}
	// Unset env var → YAML value preserved.
	if time.Duration(cfg.Scoring.ObservationWindow) != 15*time.Minute {
		t.Errorf("ObservationWindow: want 15m (from YAML), got %v", time.Duration(cfg.Scoring.ObservationWindow))
	}
}

func TestEnvOverride_InvalidIP(t *testing.T) {
	// An invalid IP address in ARXSENTINEL_WHITELIST_CUSTOM_IPS must return an error.
	t.Setenv("ARXSENTINEL_WHITELIST_CUSTOM_IPS", "1.2.3.4,not-an-ip")

	_, err := LoadConfig("/nonexistent/env-bad-ip.yaml")
	if err == nil {
		t.Error("expected error for invalid IP address, got nil")
	}
}

func TestEnvOverride_InvalidCIDR(t *testing.T) {
	// An invalid CIDR block in ARXSENTINEL_WHITELIST_CUSTOM_CIDRS must return an error.
	t.Setenv("ARXSENTINEL_WHITELIST_CUSTOM_CIDRS", "10.0.0.0/8,not-a-cidr")

	_, err := LoadConfig("/nonexistent/env-bad-cidr.yaml")
	if err == nil {
		t.Error("expected error for invalid CIDR, got nil")
	}
}

func TestEnvOverride_InvalidBool(t *testing.T) {
	// An unrecognized boolean value must return an error.
	t.Setenv("ARXSENTINEL_LOGGING_DEBUG", "yes")

	_, err := LoadConfig("/nonexistent/env-bad-bool.yaml")
	if err == nil {
		t.Error("expected error for invalid bool env var, got nil")
	}
}

func TestEnvOverride_InvalidInt(t *testing.T) {
	// A non-integer value for an int field must return an error.
	t.Setenv("ARXSENTINEL_SCORING_ALERT_THRESHOLD", "abc")

	_, err := LoadConfig("/nonexistent/env-bad-int.yaml")
	if err == nil {
		t.Error("expected error for invalid int env var, got nil")
	}
}

func TestEnvOverride_InvalidDuration(t *testing.T) {
	// An unparsable duration must return an error.
	t.Setenv("ARXSENTINEL_STATE_GC_INTERVAL", "notaduration")

	_, err := LoadConfig("/nonexistent/env-bad-dur.yaml")
	if err == nil {
		t.Error("expected error for invalid duration env var, got nil")
	}
}

// ========================== Test: BadBot defaults and env overrides ====================

func TestBadBotConfig_Defaults(t *testing.T) {
	cfg, err := LoadConfig("/nonexistent/badbot-test.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	bb := cfg.Detectors.BadBot
	if !bb.Enabled {
		t.Error("BadBot.Enabled: want true")
	}
	if bb.Score != 60 {
		t.Errorf("BadBot.Score: want 60, got %d", bb.Score)
	}
	if !bb.CheckUA {
		t.Error("BadBot.CheckUA: want true")
	}
	if bb.CheckReferrer {
		t.Error("BadBot.CheckReferrer: want false")
	}
}

func TestBlocklistConfig_Defaults(t *testing.T) {
	// Sources, refresh intervals and storage live in the blocklist: section (D6, Flow #025).
	cfg, err := LoadConfig("/nonexistent/blocklist-defaults-test.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	bl := cfg.Blocklist
	if bl.Storage != "" {
		t.Errorf("Blocklist.Storage: want empty (in-memory), got %q", bl.Storage)
	}
	if len(bl.Lists) != 2 {
		t.Fatalf("Blocklist.Lists: want 2 default lists, got %d", len(bl.Lists))
	}
	// badbot-ua list
	uaList := bl.Lists[0]
	if uaList.Name != "badbot-ua" {
		t.Errorf("Lists[0].Name: want badbot-ua, got %q", uaList.Name)
	}
	if time.Duration(uaList.RefreshInterval) != 24*time.Hour {
		t.Errorf("Lists[0].RefreshInterval: want 24h, got %v", time.Duration(uaList.RefreshInterval))
	}
	if len(uaList.Sources) != 1 || uaList.Sources[0].URL == "" {
		t.Error("Lists[0].Sources: want one non-empty URL")
	}
	if uaList.Sources[0].Format != "plain_text" {
		t.Errorf("Lists[0].Sources[0].Format: want plain_text, got %q", uaList.Sources[0].Format)
	}
	// badbot-ref list
	refList := bl.Lists[1]
	if refList.Name != "badbot-ref" {
		t.Errorf("Lists[1].Name: want badbot-ref, got %q", refList.Name)
	}
}

func TestBadBotConfig_EnvOverride(t *testing.T) {
	t.Setenv("ARXSENTINEL_DETECTORS_BADBOT_ENABLED", "false")
	t.Setenv("ARXSENTINEL_DETECTORS_BADBOT_SCORE", "99")
	t.Setenv("ARXSENTINEL_DETECTORS_BADBOT_CHECK_UA", "false")
	t.Setenv("ARXSENTINEL_DETECTORS_BADBOT_CHECK_REFERRER", "true")

	cfg, err := LoadConfig("/nonexistent/badbot-env-test.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	bb := cfg.Detectors.BadBot
	if bb.Enabled {
		t.Error("BadBot.Enabled: want false")
	}
	if bb.Score != 99 {
		t.Errorf("BadBot.Score: want 99, got %d", bb.Score)
	}
	if bb.CheckUA {
		t.Error("BadBot.CheckUA: want false")
	}
	if !bb.CheckReferrer {
		t.Error("BadBot.CheckReferrer: want true")
	}
}

func TestBlocklistConfig_EnvStorageOverride(t *testing.T) {
	// ARXSENTINEL_BLOCKLIST_STORAGE overrides the bbolt storage path for container deployments.
	t.Setenv("ARXSENTINEL_BLOCKLIST_STORAGE", "/tmp/custom-blocklist.db")

	cfg, err := LoadConfig("/nonexistent/blocklist-env-test.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Blocklist.Storage != "/tmp/custom-blocklist.db" {
		t.Errorf("Blocklist.Storage: want /tmp/custom-blocklist.db, got %q", cfg.Blocklist.Storage)
	}
}

// ── BadBot: validateConfig ────────────────────────────────────────────────────────────

func TestBadBotConfig_ValidateZeroScore(t *testing.T) {
	// score=0 must fail validation even though sources/refresh now live in blocklist:.
	path := writeTempYAML(t, `
detectors:
  badbot:
    enabled: true
    score: 0
`)
	_, err := LoadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "badbot.score") {
		t.Errorf("want error about badbot.score, got: %v", err)
	}
}

func TestBlocklistConfig_ValidateZeroRefreshInterval(t *testing.T) {
	// A list with refresh_interval=0 must fail validation (causes ticker panic).
	path := writeTempYAML(t, `
blocklist:
  lists:
    - name: test-list
      refresh_interval: 0s
      sources:
        - url: http://example.com/list.txt
          format: plain_text
`)
	_, err := LoadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "refresh_interval") {
		t.Errorf("want error about refresh_interval, got: %v", err)
	}
}

func TestBlocklistConfig_ValidateEmptySources(t *testing.T) {
	// A list without sources must fail validation.
	path := writeTempYAML(t, `
blocklist:
  lists:
    - name: test-list
      refresh_interval: 24h
      sources: []
`)
	_, err := LoadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "source") {
		t.Errorf("want error about missing sources, got: %v", err)
	}
}

func TestBlocklistConfig_ValidateEmptyListName(t *testing.T) {
	// A list with empty name must fail validation.
	path := writeTempYAML(t, `
blocklist:
  lists:
    - name: ""
      refresh_interval: 24h
      sources:
        - url: http://example.com/list.txt
          format: plain_text
`)
	_, err := LoadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "name") {
		t.Errorf("want error about empty name, got: %v", err)
	}
}

func TestBlocklistConfig_ValidateEmptySourceURL(t *testing.T) {
	// A source with empty URL must fail validation.
	path := writeTempYAML(t, `
blocklist:
  lists:
    - name: test-list
      refresh_interval: 24h
      sources:
        - url: ""
          format: plain_text
`)
	_, err := LoadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "url") {
		t.Errorf("want error about empty source URL, got: %v", err)
	}
}

// ========================== Tests: chain_guard config =================================

func TestDefaultConfig_ChainGuard(t *testing.T) {
	// Chain guard is disabled by default — enabled requires warnings_log which has no safe default.
	// When enabled, Cloudflare and bogon checks are active with sensible defaults.
	cfg, err := LoadConfig("/nonexistent/chain-guard-defaults.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cg := cfg.ChainGuard
	if cg.Enabled {
		t.Error("ChainGuard.Enabled: want false (disabled by default — requires warnings_log)")
	}
	if cg.WarningsLog != "" {
		t.Errorf("ChainGuard.WarningsLog: want empty string (default), got %q", cg.WarningsLog)
	}
	if !cg.Cloudflare.Enabled {
		t.Error("ChainGuard.Cloudflare.Enabled: want true")
	}
	if time.Duration(cg.Cloudflare.RefreshInterval) != 24*time.Hour {
		t.Errorf("ChainGuard.Cloudflare.RefreshInterval: want 24h, got %v", time.Duration(cg.Cloudflare.RefreshInterval))
	}
	if len(cg.Cloudflare.Sources) != 2 {
		t.Fatalf("ChainGuard.Cloudflare.Sources: want 2 default sources, got %d", len(cg.Cloudflare.Sources))
	}
	if !strings.Contains(cg.Cloudflare.Sources[0], "cloudflare.com") {
		t.Errorf("ChainGuard.Cloudflare.Sources[0]: want Cloudflare URL, got %q", cg.Cloudflare.Sources[0])
	}
	if !cg.Bogon.Enabled {
		t.Error("ChainGuard.Bogon.Enabled: want true")
	}
}

func TestValidateConfig_ChainGuard_MissingWarningsLog(t *testing.T) {
	// enabled=true with empty warnings_log must fail validation —
	// there is nowhere to write infrastructure alerts.
	path := writeTempYAML(t, `
chain_guard:
  enabled: true
  warnings_log: ""
  cloudflare:
    enabled: true
    refresh_interval: 24h
    sources:
      - https://www.cloudflare.com/ips-v4/
      - https://www.cloudflare.com/ips-v6/
  bogon:
    enabled: true
`)
	_, err := LoadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "chain_guard.warnings_log") {
		t.Errorf("want error about chain_guard.warnings_log, got: %v", err)
	}
}

func TestValidateConfig_ChainGuard_EmptySources(t *testing.T) {
	// cloudflare check enabled with empty sources list must fail validation —
	// the checker would never fetch fresh ranges and never signal the operator about stale data.
	path := writeTempYAML(t, `
chain_guard:
  enabled: true
  warnings_log: /var/log/arxsentinel/warnings.log
  cloudflare:
    enabled: true
    refresh_interval: 24h
    sources: []
  bogon:
    enabled: true
`)
	_, err := LoadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "chain_guard.cloudflare.sources") {
		t.Errorf("want error about chain_guard.cloudflare.sources, got: %v", err)
	}
}

func TestValidateConfig_ChainGuard_Disabled_NoWarningsLog(t *testing.T) {
	// disabled chain_guard with empty warnings_log must NOT return an error —
	// the warnings file is irrelevant when chain guard is off.
	path := writeTempYAML(t, `
chain_guard:
  enabled: false
  warnings_log: ""
  cloudflare:
    enabled: true
    refresh_interval: 24h
    sources:
      - https://www.cloudflare.com/ips-v4/
      - https://www.cloudflare.com/ips-v6/
  bogon:
    enabled: true
`)
	_, err := LoadConfig(path)
	if err != nil {
		t.Errorf("disabled chain_guard with empty warnings_log must not return error, got: %v", err)
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
