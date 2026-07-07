// ====== Module: opnsense — config =================================================
//
//	Configuration for the OPNsense firewall REST API executor — parses from
//	YAML/JSON with validation and time.Duration handling.
//
//	WHAT IS HERE:
//	  Config struct, threatLevel enum, parseConfig function, parseDurationAny
//	  helper.
//
//	WHAT IS NOT HERE:
//	  REST client (client.go, Task 3), executor logic (executor.go, Task 4),
//	  registration (register.go, Task 5).
//
//	Architectural note — see DECISIONS.md Decision 8 (Flow 096): the Config
//	struct intentionally has NO `batch_size` or `flush_interval` fields.
//	OPNsense `alias_util/add` and `alias_util/delete` apply immediately
//	(pfctl table updates per-call), so per-event point add/delete is the
//	natural model — the executor flushes nothing, every scored event becomes
//	one REST call right away. The sweep timer is derived from TTL/4 inside
//	executor.go (Task 4) with a 15m floor; it is intentionally NOT a config
//	field — see DECISIONS.md Decision 8 for the rationale.
package opnsense

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

// validSchemes enumerates the allowed values for Config.Scheme. OPNsense's
// web UI is HTTPS by default; "http" is kept as an opt-in for lab setups and
// integration mocks (mirrors the openwrt convention).
var validSchemes = map[string]struct{}{
	"http":  {},
	"https": {},
}

// ++++++++++++++++++++++++++ Configuration struct ++++++++++++++++++++++++++

// Config contains settings for connecting to an OPNsense firewall over its
// REST API and managing a single alias for IP blocking.
//
// The executor targets the `alias_util` endpoints:
//   - POST /api/firewall/alias_util/add/{alias_name}   {"address":"1.2.3.4"}
//   - POST /api/firewall/alias_util/delete/{alias_name} {"address":"1.2.3.4"}
//   - GET  /api/firewall/alias_util/list/{alias_name}
//
// Authentication is HTTP Basic with the OPNsense API credentials
// (User Manager → API section: API key is the username, API secret is the
// password). The alias_name must be a pre-existing alias of type Host,
// Network, or External — see DECISIONS.md Decision 3 and the package README
// for the type-restriction rationale.
type Config struct {
	// Host is the firewall address (hostname or IP). Required.
	Host string `json:"host" yaml:"host"`
	// Port is the HTTPS port of the OPNsense web UI. Default: 443.
	Port int `json:"port" yaml:"port"`
	// Scheme is "http" or "https". Default: "https". HTTP is for lab setups
	// and integration mocks; production OPNsense deployments are HTTPS-only.
	Scheme string `json:"scheme" yaml:"scheme"`
	// APIKey is the OPNsense API username (Basic Auth). Required.
	// Generated in User Manager → API section.
	APIKey string `json:"api_key" yaml:"api_key"`
	// APISecret is the OPNsense API password (Basic Auth). Required.
	APISecret string `json:"api_secret" yaml:"api_secret"`
	// TLSVerify controls verification of the OPNsense TLS certificate.
	// Default: true. OPNsense ships with a self-signed certificate by
	// default, so production users frequently flip this to false or supply
	// a CA via the system trust store; the option is exposed as-is and the
	// client implementation in Task 3 will read it directly.
	TLSVerify bool `json:"tls_verify" yaml:"tls_verify"`
	// AliasName is the firewall alias the executor manages. Required. The
	// alias must be pre-declared in the OPNsense UI as type Host, Network,
	// or External — see DECISIONS.md Decision 3.
	AliasName string `json:"alias_name" yaml:"alias_name"`
	// TTL is the lifetime of a ban. REQUIRED — must be > 0. The executor
	// performs an active TTL-sweep with independent delete calls per
	// expired entry (see DECISIONS.md Decision 1 — mikrotik-style, not
	// openwrt batching).
	TTL time.Duration `json:"-" yaml:"ttl"`
	// MinLevel filters incoming events by minimum threat level. Allowed
	// values: INFO, WARN, THREAT. Default: THREAT.
	MinLevel string `json:"min_level" yaml:"min_level"`
	// DedupWindow skips re-banning an IP within this window after a
	// successful ban. 0 means disabled. Mirrors the mikrotik/openwrt
	// rationale: avoid hammering the OPNsense API with redundant
	// alias_util/add calls when the same attacking IP is reported
	// repeatedly within a short period.
	DedupWindow time.Duration `json:"-" yaml:"dedup_window"`
}

// ++++++++++++++++++++++++++ Defaults ++++++++++++++++++++++++++++++++++++++++

func defaultConfig() Config {
	return Config{
		Port:      443,
		Scheme:    "https",
		TLSVerify: true,
		MinLevel:  "THREAT",
	}
}

// ++++++++++++++++++++++++++ Configuration parsing ++++++++++++++++++++++++++

// parseConfig converts a raw map (from yaml.Unmarshal) into a Config struct.
//
// Mirrors the openwrt pattern: extract time.Duration fields BEFORE the json
// round-trip (time.Duration doesn't serialize natively through JSON), then
// unmarshal the remaining primitives, then validate required fields and
// enum values.
func parseConfig(raw map[string]any) (Config, error) {
	cfg := defaultConfig()

	// Copy so deletions don't mutate the caller's map.
	rawCopy := make(map[string]any, len(raw))
	for k, v := range raw {
		rawCopy[k] = v
	}

	// TTL: REQUIRED (see DECISIONS.md Decision 1 / Decision 8 — TTL must be
	// > 0, the plugin owns expiry tracking).
	if ttlVal, ok := rawCopy["ttl"]; ok {
		delete(rawCopy, "ttl")
		d, err := parseDurationAny(ttlVal)
		if err != nil {
			return Config{}, fmt.Errorf("opnsense: parseConfig: invalid ttl: %w", err)
		}
		cfg.TTL = d
	}

	// DedupWindow: optional, default 0 (disabled).
	if dwVal, ok := rawCopy["dedup_window"]; ok {
		delete(rawCopy, "dedup_window")
		d, err := parseDurationAny(dwVal)
		if err != nil {
			return Config{}, fmt.Errorf("opnsense: parseConfig: invalid dedup_window: %w", err)
		}
		cfg.DedupWindow = d
	}

	rawJSON, err := json.Marshal(rawCopy)
	if err != nil {
		return Config{}, fmt.Errorf("opnsense: parseConfig: marshal: %w", err)
	}
	if err := json.Unmarshal(rawJSON, &cfg); err != nil {
		return Config{}, fmt.Errorf("opnsense: parseConfig: unmarshal: %w", err)
	}

	// ++++++++++++++++++++++++++ Validation +++++++++++++++++++++++++++++++++++
	if cfg.Host == "" {
		return Config{}, fmt.Errorf("opnsense: parseConfig: host must not be empty")
	}
	if cfg.APIKey == "" {
		return Config{}, fmt.Errorf("opnsense: parseConfig: api_key must not be empty")
	}
	if cfg.APISecret == "" {
		return Config{}, fmt.Errorf("opnsense: parseConfig: api_secret must not be empty")
	}
	if cfg.AliasName == "" {
		return Config{}, fmt.Errorf("opnsense: parseConfig: alias_name must not be empty")
	}
	// TTL is mandatory and must be > 0 — see DECISIONS.md Decision 8
	// (the plugin owns expiry tracking; no native nftables/pf timeout fallback).
	if cfg.TTL <= 0 {
		return Config{}, fmt.Errorf("opnsense: parseConfig: ttl must be > 0, got %s", cfg.TTL)
	}
	if _, ok := validSchemes[cfg.Scheme]; !ok {
		return Config{}, fmt.Errorf("opnsense: parseConfig: invalid scheme %q, must be \"http\" or \"https\"", cfg.Scheme)
	}
	if _, ok := levelOrder[cfg.MinLevel]; !ok {
		return Config{}, fmt.Errorf("opnsense: parseConfig: invalid MinLevel %q, must be INFO, WARN or THREAT", cfg.MinLevel)
	}

	return cfg, nil
}

// parseDurationAny accepts either a string (e.g. "24h", "30m") or an int
// (interpreted as seconds) — the same shape YAML/JSON unmarshalling can
// produce for a time.Duration-like field. Used by parseConfig to extract
// the duration fields before the JSON round-trip (time.Duration is not a
// built-in JSON type). Mirrors the openwrt helper verbatim — kept local
// (not exported) because it's a small utility and each plugin package
// stands on its own.
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
