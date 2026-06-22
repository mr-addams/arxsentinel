// ====== Module: mikrotik — config ===============================================
//   Configuration for MikroTik RouterOS REST API executor — parses from
//   YAML/JSON with validation and time.Duration handling.
//
//   WHAT IS HERE:
//     Config struct, threatLevel enum, parseConfig function
//
//   WHAT IS NOT HERE:
//     HTTP client (client.go), executor logic (executor.go), registration (register.go)

package mikrotik

import (
	"encoding/json"
	"fmt"
	"time"
)

// ========================== Config ==========================

// ++++++++++++++++++++++++++ Level helpers +++++++++++++++++++++++++++++++++++

type threatLevel int

const (
	levelInfo threatLevel = iota
	levelWarn
	levelThreat
)

var levelOrder = map[string]threatLevel{
	"INFO":   levelInfo,
	"WARN":   levelWarn,
	"THREAT": levelThreat,
}

// ++++++++++++++++++++++++++ Configuration struct ++++++++++++++++++++++++++

// Config contains settings for connecting to a MikroTik RouterOS device via
// REST API and managing an address-list for IP blocking.
type Config struct {
	Host       string        `json:"host" yaml:"host"`
	Port       int           `json:"port" yaml:"port"`
	Username   string        `json:"username" yaml:"username"`
	Password   string        `json:"password" yaml:"password"`
	ListName   string        `json:"list_name" yaml:"list_name"`
	TTL        time.Duration `json:"-" yaml:"ttl"`
	SentinelID string        `json:"sentinel_id" yaml:"sentinel_id"`
	TLSVerify  bool          `json:"tls_verify" yaml:"tls_verify"`
	// CAFile is the path to a PEM-encoded CA certificate file used to verify the
	// RouterOS TLS certificate. If empty, the system trust store is used.
	// Required when tls_verify: true and the RouterOS cert is signed by an internal CA.
	CAFile string `json:"ca_file" yaml:"ca_file"`
	// UseTLS controls whether to use HTTPS (true, default) or plain HTTP (false).
	// Set to false only for local mock servers in integration tests.
	UseTLS        bool          `json:"use_tls" yaml:"use_tls"`
	BatchSize     int           `json:"batch_size" yaml:"batch_size"`
	FlushInterval time.Duration `json:"-" yaml:"flush_interval"`
	MinLevel      string        `json:"min_level" yaml:"min_level"`
	// DedupWindow skips re-banning an IP within this window after a successful ban.
	// 0 means disabled (only banned-map dedup is applied). This prevents hammering the
	// RouterOS API with redundant Add calls when the same attacking IP is reported
	// repeatedly within a short period.
	DedupWindow time.Duration `json:"-" yaml:"dedup_window"`
}

// ++++++++++++++++++++++++++ Defaults ++++++++++++++++++++++++++++++++++++++++

func defaultConfig() Config {
	return Config{
		Port:          443,
		ListName:      "arxsentinel_blocklist",
		TTL:           24 * time.Hour,
		TLSVerify:     true,
		UseTLS:        true,
		BatchSize:     10,
		FlushInterval: 30 * time.Second,
		MinLevel:      "THREAT",
	}
}

// ++++++++++++++++++++++++++ Configuration parsing ++++++++++++++++++++++++++

// parseConfig converts a raw map (from yaml.Unmarshal) into a Config struct.
func parseConfig(raw map[string]any) (Config, error) {
	cfg := defaultConfig()

	rawCopy := make(map[string]any, len(raw))
	for k, v := range raw {
		rawCopy[k] = v
	}

	if ttlVal, ok := rawCopy["ttl"]; ok {
		delete(rawCopy, "ttl")
		switch v := ttlVal.(type) {
		case string:
			d, err := time.ParseDuration(v)
			if err != nil {
				return Config{}, fmt.Errorf("mikrotik: parseConfig: invalid ttl format %q: %w", v, err)
			}
			cfg.TTL = d
		case int:
			cfg.TTL = time.Duration(v) * time.Second
		}
	}

	if fiVal, ok := rawCopy["flush_interval"]; ok {
		delete(rawCopy, "flush_interval")
		switch v := fiVal.(type) {
		case string:
			d, err := time.ParseDuration(v)
			if err != nil {
				return Config{}, fmt.Errorf("mikrotik: parseConfig: invalid flush_interval format %q: %w", v, err)
			}
			cfg.FlushInterval = d
		case int:
			cfg.FlushInterval = time.Duration(v) * time.Second
		}
	}

	// DedupWindow: optional, default 0 (disabled).
	// Парсим так же, как flush_interval — отдельная ветка до JSON round-trip,
	// потому что time.Duration не сериализуется нативно.
	if dwVal, ok := rawCopy["dedup_window"]; ok {
		delete(rawCopy, "dedup_window")
		switch v := dwVal.(type) {
		case string:
			d, err := time.ParseDuration(v)
			if err != nil {
				return Config{}, fmt.Errorf("mikrotik: parseConfig: invalid dedup_window format %q: %w", v, err)
			}
			cfg.DedupWindow = d
		case int:
			cfg.DedupWindow = time.Duration(v) * time.Second
		}
	}

	rawJSON, err := json.Marshal(rawCopy)
	if err != nil {
		return Config{}, fmt.Errorf("mikrotik: parseConfig: marshal: %w", err)
	}
	if err := json.Unmarshal(rawJSON, &cfg); err != nil {
		return Config{}, fmt.Errorf("mikrotik: parseConfig: unmarshal: %w", err)
	}

	if cfg.Host == "" {
		return Config{}, fmt.Errorf("mikrotik: parseConfig: host must not be empty")
	}
	if cfg.Username == "" {
		return Config{}, fmt.Errorf("mikrotik: parseConfig: username must not be empty")
	}
	if cfg.Password == "" {
		return Config{}, fmt.Errorf("mikrotik: parseConfig: password must not be empty")
	}
	if cfg.SentinelID == "" {
		return Config{}, fmt.Errorf("mikrotik: parseConfig: sentinel_id must not be empty")
	}
	if _, ok := levelOrder[cfg.MinLevel]; !ok {
		return Config{}, fmt.Errorf("mikrotik: parseConfig: invalid MinLevel %q, must be INFO, WARN or THREAT", cfg.MinLevel)
	}

	return cfg, nil
}
