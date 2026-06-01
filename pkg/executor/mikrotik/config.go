// ========================== Package mikrotik ==========================
//   Configuration for MikroTik RouterOS REST API executor — parses from
//   YAML/JSON with validation and time.Duration handling.

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
	levelInfo   threatLevel = iota
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
	Host          string        `json:"host" yaml:"host"`
	Port          int           `json:"port" yaml:"port"`
	Username      string        `json:"username" yaml:"username"`
	Password      string        `json:"password" yaml:"password"`
	ListName      string        `json:"list_name" yaml:"list_name"`
	TTL           time.Duration `json:"-" yaml:"ttl"`
	SentinelID    string        `json:"sentinel_id" yaml:"sentinel_id"`
	TLSVerify     bool          `json:"tls_verify" yaml:"tls_verify"`
	// UseTLS controls whether to use HTTPS (true, default) or plain HTTP (false).
	// Set to false only for local mock servers in integration tests.
	UseTLS        bool          `json:"use_tls" yaml:"use_tls"`
	BatchSize     int           `json:"batch_size" yaml:"batch_size"`
	FlushInterval time.Duration `json:"-" yaml:"flush_interval"`
	MinLevel      string        `json:"min_level" yaml:"min_level"`
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