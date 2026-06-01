// ========================== Package nginx ==========================
//   Configuration for nginx geo-block executor — parses from YAML/JSON
//   with validation of required fields and time.Duration handling.
//
//   WHAT IS HERE:
//     - Config — configuration struct with json and yaml tags
//     - parseConfig — parsing from map[string]any with defaults and validation
//
//   WHAT IS NOT HERE:
//     - Executor implementation (see executor.go)
//     - Registration (see register.go)

package nginx

import (
	// ── Group 1: standard library ──
	"encoding/json"
	"fmt"
	"time"
)

// ========================== Config ==========================

// ++++++++++++++++++++++++++ Configuration struct ++++++++++++++++++++++++++

// Config contains settings for the nginx geo-block executor.
// All duration fields are tagged json:"-" because encoding/json cannot
// convert strings to time.Duration — they are parsed separately in parseConfig.
type Config struct {
	// ListFile is the path to the geo-block file that nginx includes.
	// Required. Format: one "<ip> 1;" per line, managed by this executor.
	ListFile string `json:"list_file" yaml:"list_file"`
	// StateFile is the optional path for JSON TTL persistence.
	// If set, the executor writes a map of {"ip": "timestamp"} after every flush/sweep.
	// If empty, TTL is calculated from process start time.
	StateFile string `json:"state_file" yaml:"state_file"`
	// MinLevel sets the minimum threat level for adding an IP;
	// one of "INFO", "WARN", "THREAT". Default "THREAT".
	MinLevel string `json:"min_level" yaml:"min_level"`
	// TTL is the auto-unban duration. Default 24h.
	TTL time.Duration `json:"-" yaml:"ttl"`
	// BatchSize limits the number of events accumulated before flushing to file. Default 10.
	BatchSize int `json:"batch_size" yaml:"batch_size"`
	// FlushInterval is the maximum time between partial batch flushes. Default 30s.
	FlushInterval time.Duration `json:"-" yaml:"flush_interval"`
	// ReloadCmd is the shell command to reload nginx after a file write.
	// Empty string means passive mode (no auto-reload, WARNING logged at startup).
	ReloadCmd string `json:"reload_cmd" yaml:"reload_cmd"`
	// ReloadTimeout limits how long the reload command may run. Default 30s.
	ReloadTimeout time.Duration `json:"-" yaml:"reload_timeout"`
}

// ++++++++++++++++++++++++++ Defaults ++++++++++++++++++++++++++++++++++++++++

// DefaultConfig returns a Config with all defaults populated.
func DefaultConfig() Config {
	return Config{
		MinLevel:      "THREAT",
		TTL:           24 * time.Hour,
		BatchSize:     10,
		FlushInterval: 30 * time.Second,
		ReloadTimeout: 30 * time.Second,
	}
}

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

// ++++++++++++++++++++++++++ Configuration parsing ++++++++++++++++++++++++++

// parseConfig converts a raw map (from yaml.Unmarshal) into a Config struct.
//
//	Workflow:
//	1. Sets default values
//	2. Extracts and parses duration fields (ttl, flush_interval, reload_timeout)
//	   from the map before JSON serialization
//	3. Marshals remaining fields to JSON and unmarshals into Config
//	4. Validates required fields (ListFile) and MinLevel values
func parseConfig(raw map[string]any) (Config, error) {
	// ---- Default values ----
	cfg := DefaultConfig()

	// ---- Duration fields: parse before JSON serialization ----
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
				return Config{}, fmt.Errorf("nginx: parseConfig: invalid ttl format %q: %w", v, err)
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
				return Config{}, fmt.Errorf("nginx: parseConfig: invalid flush_interval format %q: %w", v, err)
			}
			cfg.FlushInterval = d
		case int:
			cfg.FlushInterval = time.Duration(v) * time.Second
		}
	}

	if rtVal, ok := rawCopy["reload_timeout"]; ok {
		delete(rawCopy, "reload_timeout")
		switch v := rtVal.(type) {
		case string:
			d, err := time.ParseDuration(v)
			if err != nil {
				return Config{}, fmt.Errorf("nginx: parseConfig: invalid reload_timeout format %q: %w", v, err)
			}
			cfg.ReloadTimeout = d
		case int:
			cfg.ReloadTimeout = time.Duration(v) * time.Second
		}
	}

	// ---- JSON round-trip for remaining fields ----
	rawJSON, err := json.Marshal(rawCopy)
	if err != nil {
		return Config{}, fmt.Errorf("nginx: parseConfig: marshal: %w", err)
	}
	if err := json.Unmarshal(rawJSON, &cfg); err != nil {
		return Config{}, fmt.Errorf("nginx: parseConfig: unmarshal: %w", err)
	}

	// ---- Required field validation ----
	if cfg.ListFile == "" {
		return Config{}, fmt.Errorf("nginx: parseConfig: list_file must not be empty")
	}
	if _, ok := levelOrder[cfg.MinLevel]; !ok {
		return Config{}, fmt.Errorf("nginx: parseConfig: invalid MinLevel %q, must be INFO, WARN or THREAT", cfg.MinLevel)
	}

	return cfg, nil
}
