// ========================== Тесты модуля config ========================================
//   Проверяет LoadConfig: дефолты, переопределение из YAML, парсинг Duration.
//
//   Тест-конфиги полные (все поля секции) — из-за ограничения yaml.v3 partial merge.
//   Секции, отсутствующие в YAML, сохраняют Go-дефолты.

package config

import (
	"os"
	"strings"
	"testing"
	"time"
)

// ========================== Тест: дефолты без файла ====================================

func TestLoadConfig_Defaults(t *testing.T) {
	// Несуществующий путь → LoadConfig должен вернуть дефолты без ошибки.
	// Это позволяет демону стартовать "из коробки" без config.yaml.
	cfg, err := LoadConfig("/nonexistent/path/nginx-sentinel-test-config.yaml")
	if err != nil {
		t.Fatalf("несуществующий конфиг должен возвращать дефолты без ошибки, получили: %v", err)
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

// ========================== Тест: переопределение из YAML ==============================

func TestLoadConfig_Override(t *testing.T) {
	// YAML содержит полные секции scoring и logging — частичные секции не тестируем
	// из-за ограничения yaml.v3 (partial section zeroes unmentioned fields).
	// Секции state и detectors в YAML отсутствуют → должны сохранить дефолты.
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

	// ── Переопределённые значения ─────────────────────────────────────────────────────

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

	// ── Секции без YAML → сохраняют дефолты ──────────────────────────────────────────

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

// ========================== Тест: Duration из YAML =====================================

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

// ========================== Тест: невалидный YAML ======================================

func TestLoadConfig_InvalidYAML(t *testing.T) {
	f := writeTempYAML(t, "{ invalid yaml: [unclosed")
	defer os.Remove(f)

	_, err := LoadConfig(f)
	if err == nil {
		t.Error("невалидный YAML должен возвращать ошибку")
	}
}

// ========================== Тест: корректность дефолтов ботов ==========================

func TestLoadConfig_DefaultBots(t *testing.T) {
	cfg, err := LoadConfig("/nonexistent")
	if err != nil {
		t.Fatalf("LoadConfig с несуществующим файлом должен вернуть дефолты без ошибки: %v", err)
	}

	// Проверяем что ключевые боты присутствуют
	found := map[string]bool{}
	for _, b := range cfg.Whitelist.Bots {
		found[b.Name] = true
	}

	required := []string{"google", "bing", "yandex", "gptbot", "claudebot"}
	for _, name := range required {
		if !found[name] {
			t.Errorf("Whitelist.Bots: бот %q не найден в дефолтах", name)
		}
	}

	// Google должен использовать rdns_ipjson верификацию
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

// ========================== Тест: stderr при отсутствии конфига ========================

func TestLoadConfig_StderrOnMissingFile(t *testing.T) {
	// При ENOENT LoadConfig должен выводить сообщение в stderr —
	// оператор должен знать что демон работает на дефолтах, а не на его config.yaml.

	// Перехватываем os.Stderr через pipe
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

	if !strings.Contains(output, "не найден, используются дефолты") {
		t.Errorf("stderr должен содержать 'не найден, используются дефолты', получили: %q", output)
	}
}

// ========================== Хелпер ====================================================

// writeTempYAML создаёт временный файл с содержимым content и возвращает его путь.
func writeTempYAML(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp("", "nginx-sentinel-test-*.yaml")
	if err != nil {
		t.Fatalf("не удалось создать temp файл: %v", err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatalf("запись в temp файл: %v", err)
	}
	f.Close()
	return f.Name()
}
