// ====== Module: openwrt — config =================================================
//   Configuration for the OpenWrt ubus executor — parses from YAML/JSON with
//   validation and time.Duration handling.
//
//   WHAT IS HERE:
//     Config struct, threatLevel enum, parseConfig function
//
//   WHAT IS NOT HERE:
//     ubus client (client.go), executor logic (executor.go), registration (register.go)

package openwrt

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

// Config contains settings for connecting to an OpenWrt router via ubus
// (uhttpd-mod-ubus) and managing an nftables ipset for IP blocking.
//
// The executor performs UCI edits on a user-declared ipset section
// (firewall.@ipset[N]) via the standard rpcd core-object "uci" (get / add /
// set / add_list / del_list / commit) and applies the change with a single
// rc.init(reload) call — see DECISIONS.md Decision 3 and Decision 4.
type Config struct {
	// Host is the router address (hostname or IP). Required.
	Host string `json:"host" yaml:"host"`
	// Port is the HTTP port of uhttpd-mod-ubus. Default: 80.
	Port int `json:"port" yaml:"port"`
	// Scheme is "http" or "https". Default: "http".
	// HTTPS is rarely used in default OpenWrt setups; flip when the
	// router's uhttpd is fronted by TLS.
	Scheme string `json:"scheme" yaml:"scheme"`
	// Username and Password are the rpcd credentials. Required.
	Username string `json:"username" yaml:"username"`
	Password string `json:"password" yaml:"password"`
	// IPSetName is the value of the `option name` field in the
	// firewall.@ipset[N] UCI section. The user must declare the section
	// ahead of time; the plugin does not create it. Required.
	IPSetName string `json:"ipset_name" yaml:"ipset_name"`
	// TTL is the lifetime of a ban. REQUIRED — must be > 0. The executor
	// performs an active batched sweep against this TTL (local tracking,
	// not nftables-native timeout) — see DECISIONS.md Decision 4.
	TTL time.Duration `json:"-" yaml:"ttl"`
	// SessionTimeout is the lifetime of an ubus_rpc_session token
	// (default 5m in uhttpd-mod-ubus). The client should re-authorize
	// before this elapses. Configurable for environments with custom
	// rpcd session timeouts. Default: 5m.
	SessionTimeout time.Duration `json:"-" yaml:"session_timeout"`
	// BatchSize caps the number of pending add/del operations per flush.
	// 0 or negative → use default. Default: 10.
	BatchSize int `json:"batch_size" yaml:"batch_size"`
	// FlushInterval is the maximum time between two flushes. Default: 30s.
	FlushInterval time.Duration `json:"-" yaml:"flush_interval"`
	// MinLevel filters incoming events by minimum threat level. Allowed
	// values: INFO, WARN, THREAT. Default: THREAT.
	MinLevel string `json:"min_level" yaml:"min_level"`
	// DedupWindow skips re-banning an IP within this window after a
	// successful ban. 0 means disabled. See mikrotik equivalent for
	// rationale (avoid hammering ubus with redundant add_list calls).
	DedupWindow time.Duration `json:"-" yaml:"dedup_window"`
}

// ++++++++++++++++++++++++++ Defaults ++++++++++++++++++++++++++++++++++++++++

func defaultConfig() Config {
	return Config{
		Port:           80,
		Scheme:         "http",
		SessionTimeout: 5 * time.Minute,
		BatchSize:      10,
		FlushInterval:  30 * time.Second,
		MinLevel:       "THREAT",
	}
}

// ++++++++++++++++++++++++++ Configuration parsing ++++++++++++++++++++++++++

// parseConfig converts a raw map (from yaml.Unmarshal) into a Config struct.
//
// Mirrors the mikrotik pattern: extract time.Duration fields BEFORE the
// json round-trip (time.Duration doesn't serialize natively through JSON),
// then unmarshal the remaining primitives, then validate required fields
// and enum values.
func parseConfig(raw map[string]any) (Config, error) {
	cfg := defaultConfig()

	// Copy so deletions don't mutate the caller's map.
	rawCopy := make(map[string]any, len(raw))
	for k, v := range raw {
		rawCopy[k] = v
	}

	// TTL: REQUIRED (see DECISIONS.md Decision 4 — TTL must be > 0).
	if ttlVal, ok := rawCopy["ttl"]; ok {
		delete(rawCopy, "ttl")
		d, err := parseDurationAny(ttlVal)
		if err != nil {
			return Config{}, fmt.Errorf("openwrt: parseConfig: invalid ttl: %w", err)
		}
		cfg.TTL = d
	}

	if stVal, ok := rawCopy["session_timeout"]; ok {
		delete(rawCopy, "session_timeout")
		d, err := parseDurationAny(stVal)
		if err != nil {
			return Config{}, fmt.Errorf("openwrt: parseConfig: invalid session_timeout: %w", err)
		}
		cfg.SessionTimeout = d
	}

	if fiVal, ok := rawCopy["flush_interval"]; ok {
		delete(rawCopy, "flush_interval")
		d, err := parseDurationAny(fiVal)
		if err != nil {
			return Config{}, fmt.Errorf("openwrt: parseConfig: invalid flush_interval: %w", err)
		}
		cfg.FlushInterval = d
	}

	// DedupWindow: optional, default 0 (disabled).
	if dwVal, ok := rawCopy["dedup_window"]; ok {
		delete(rawCopy, "dedup_window")
		d, err := parseDurationAny(dwVal)
		if err != nil {
			return Config{}, fmt.Errorf("openwrt: parseConfig: invalid dedup_window: %w", err)
		}
		cfg.DedupWindow = d
	}

	rawJSON, err := json.Marshal(rawCopy)
	if err != nil {
		return Config{}, fmt.Errorf("openwrt: parseConfig: marshal: %w", err)
	}
	if err := json.Unmarshal(rawJSON, &cfg); err != nil {
		return Config{}, fmt.Errorf("openwrt: parseConfig: unmarshal: %w", err)
	}

	// ++++++++++++++++++++++++++ Validation +++++++++++++++++++++++++++++++++++
	if cfg.Host == "" {
		return Config{}, fmt.Errorf("openwrt: parseConfig: host must not be empty")
	}
	if cfg.Username == "" {
		return Config{}, fmt.Errorf("openwrt: parseConfig: username must not be empty")
	}
	if cfg.Password == "" {
		return Config{}, fmt.Errorf("openwrt: parseConfig: password must not be empty")
	}
	if cfg.IPSetName == "" {
		return Config{}, fmt.Errorf("openwrt: parseConfig: ipset_name must not be empty")
	}
	// TTL is mandatory and must be > 0 — see DECISIONS.md Decision 4
	// (the plugin owns expiry tracking; no native nftables timeout fallback).
	if cfg.TTL <= 0 {
		return Config{}, fmt.Errorf("openwrt: parseConfig: ttl must be > 0, got %s", cfg.TTL)
	}
	// SessionTimeout must be positive when set; the default (5m) satisfies this.
	if cfg.SessionTimeout <= 0 {
		return Config{}, fmt.Errorf("openwrt: parseConfig: session_timeout must be > 0, got %s", cfg.SessionTimeout)
	}
	if cfg.Scheme != "http" && cfg.Scheme != "https" {
		return Config{}, fmt.Errorf("openwrt: parseConfig: invalid scheme %q, must be \"http\" or \"https\"", cfg.Scheme)
	}
	if _, ok := levelOrder[cfg.MinLevel]; !ok {
		return Config{}, fmt.Errorf("openwrt: parseConfig: invalid MinLevel %q, must be INFO, WARN or THREAT", cfg.MinLevel)
	}

	return cfg, nil
}

// parseDurationAny accepts either a string (e.g. "24h", "30m") or an int
// (interpreted as seconds) — the same shape YAML/JSON unmarshalling can
// produce for a time.Duration-like field. Used by parseConfig to extract
// the duration fields before the JSON round-trip (time.Duration is not a
// built-in JSON type).
func parseDurationAny(v any) (time.Duration, error) {
	switch x := v.(type) {
	case string:
		if x == "" {
			return 0, fmt.Errorf("empty duration string")
		}
		d, err := time.ParseDuration(x)
		if err != nil {
			return 0, err
		}
		return d, nil
	case int:
		return time.Duration(x) * time.Second, nil
	case int64:
		return time.Duration(x) * time.Second, nil
	case float64:
		// YAML often decodes numeric values as float64.
		return time.Duration(x) * time.Second, nil
	default:
		return 0, fmt.Errorf("unsupported duration type %T", v)
	}
}
