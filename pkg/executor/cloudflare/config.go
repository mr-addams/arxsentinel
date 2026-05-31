// ========================== Package cloudflare ==========================
//   Configuration for Cloudflare API communication — parses from YAML/JSON
//   with validation of required fields and time.Duration handling.
//
//   WHAT IS HERE:
//     - Config — configuration struct with json and yaml tags
//     - parseConfig — parsing from map[string]interface{} with defaults and validation
//
//   WHAT IS NOT HERE:
//     - HTTP client implementation (see client.go)
//     - IP list sync logic (see syncer.go)

package cloudflare

import (
	// ── Group 1: standard library ──
	"encoding/json"
	"fmt"
	"time"
)

// ========================== Config ==========================

// ++++++++++++++++++++++++++ Configuration struct ++++++++++++++++++++++++++

// Config contains settings for connecting to the Cloudflare API and managing
// IP lists. Fields can be populated from both YAML and JSON.
// APIToken and AccountID are read from external config instead of environment
// variables to support multi-executor configs without env-var collisions.
type Config struct {
	// APIToken authenticates all requests to the Cloudflare API — required,
	// created in Cloudflare Dashboard → API Tokens with list editing permissions.
	APIToken string `json:"api_token" yaml:"api_token"`
	// AccountID identifies the Cloudflare account — required, visible in the
	// right panel of Cloudflare Dashboard → Account ID.
	AccountID string `json:"account_id" yaml:"account_id"`
	// ListName specifies the IP-list name in Cloudflare — used as a key
	// to identify the list during updates; defaults to "arxsentinel-blocklist".
	ListName string `json:"list_name" yaml:"list_name"`
	// MinLevel sets the minimum threat level for adding an IP to the block-list;
	// value "THREAT" includes all threats except "INFO".
	MinLevel string `json:"min_level" yaml:"min_level"`
	// TTL sets the in-memory cache lifetime for the list — parsed separately from
	// the raw config via time.ParseDuration, therefore has no json tag.
	TTL time.Duration `json:"-" yaml:"ttl"`
	// MaxItems limits the number of items in the IP list (0 = no limit);
	// protects against Cloudflare API quota overflow (maximum 10 000 entries).
	MaxItems int `json:"max_items" yaml:"max_items"`
	// DedupWindow skips re-banning an IP within this window after a successful ban;
	// 0 means disabled. Applied on top of the existing banned-map dedup — even after
	// the IP is removed from the banned map (TTL sweep), it won't be re-banned until
	// DedupWindow expires.
	DedupWindow time.Duration `json:"-" yaml:"dedup_window"`
	// BatchSize limits the number of ThreatEvents accumulated before flushing to
	// the Cloudflare API. Default 100. CF API limit is 1000 items per request.
	BatchSize int `json:"batch_size" yaml:"batch_size"`
	// FlushInterval is the maximum time between batch flushes. If BatchSize is not
	// reached within this interval, a partial batch is flushed regardless.
	FlushInterval time.Duration `json:"-" yaml:"flush_interval"`
	// InstanceID overrides the auto-detected instance ID. Useful for cleanup
	// or when running multiple instances on the same machine.
	InstanceID string `json:"instance_id" yaml:"instance_id"`
}

// ++++++++++++++++++++++++++ Defaults ++++++++++++++++++++++++++++++++++++++++

// DefaultConfig returns a Config with all defaults populated.
func DefaultConfig() Config {
	return Config{
		ListName:      "arxsentinel-blocklist",
		MinLevel:      "THREAT",
		TTL:           24 * time.Hour,
		MaxItems:      0,
		BatchSize:     100,
		FlushInterval: 10 * time.Second,
	}
}

// ++++++++++++++++++++++++++ Configuration parsing ++++++++++++++++++++++++++

// parseConfig converts a raw map (from yaml.Unmarshal) into a Config struct.
//
//	Workflow:
//	1. Sets default values
//	2. Extracts and parses TTL (time.Duration) from the map — before JSON serialization,
//	   because encoding/json cannot convert a string to Duration
//	3. Marshals remaining fields to JSON and unmarshals into Config
//	4. Validates required fields (APIToken, AccountID)
func parseConfig(raw map[string]interface{}) (Config, error) {
	// ---- Default values ----
	cfg := Config{
		ListName:      "arxsentinel-blocklist",
		MinLevel:      "THREAT",
		TTL:           24 * time.Hour,
		MaxItems:      0,
		BatchSize:     100,
		FlushInterval: 10 * time.Second,
	}

	// ---- Duration fields: parse before JSON serialization ----
	// Copy the map to avoid mutating the original (the caller may need it
	// for logging).
	rawCopy := make(map[string]interface{}, len(raw))
	for k, v := range raw {
		rawCopy[k] = v
	}

	if ttlVal, ok := rawCopy["ttl"]; ok {
		delete(rawCopy, "ttl")
		switch v := ttlVal.(type) {
		case string:
			d, err := time.ParseDuration(v)
			if err != nil {
				return Config{}, fmt.Errorf(
					"cloudflare: parseConfig: invalid ttl format %q: %w", v, err,
				)
			}
			cfg.TTL = d
		case int:
			cfg.TTL = time.Duration(v) * time.Second
		}
	}

	if dwVal, ok := rawCopy["dedup_window"]; ok {
		delete(rawCopy, "dedup_window")
		switch v := dwVal.(type) {
		case string:
			d, err := time.ParseDuration(v)
			if err != nil {
				return Config{}, fmt.Errorf(
					"cloudflare: parseConfig: invalid dedup_window format %q: %w", v, err,
				)
			}
			cfg.DedupWindow = d
		case int:
			cfg.DedupWindow = time.Duration(v) * time.Second
		}
	}

	if fiVal, ok := rawCopy["flush_interval"]; ok {
		delete(rawCopy, "flush_interval")
		switch v := fiVal.(type) {
		case string:
			d, err := time.ParseDuration(v)
			if err != nil {
				return Config{}, fmt.Errorf(
					"cloudflare: parseConfig: invalid flush_interval format %q: %w", v, err,
				)
			}
			cfg.FlushInterval = d
		case int:
			cfg.FlushInterval = time.Duration(v) * time.Second
		}
	}

	// ---- JSON round-trip for remaining fields ----
	// Pass the map through JSON to leverage the standard unmarshaler with
	// all tags and default values.
	rawJSON, err := json.Marshal(rawCopy)
	if err != nil {
		return Config{}, fmt.Errorf("cloudflare: parseConfig: marshal: %w", err)
	}
	if err := json.Unmarshal(rawJSON, &cfg); err != nil {
		return Config{}, fmt.Errorf("cloudflare: parseConfig: unmarshal: %w", err)
	}

	// ---- Required field validation ----
	if cfg.APIToken == "" {
		return Config{}, fmt.Errorf("cloudflare: parseConfig: APIToken must not be empty")
	}
	if cfg.AccountID == "" {
		return Config{}, fmt.Errorf("cloudflare: parseConfig: AccountID must not be empty")
	}
	// Validate MinLevel — must be one of the known threat levels.
	if _, ok := levelOrder[cfg.MinLevel]; !ok {
		return Config{}, fmt.Errorf("cloudflare: parseConfig: invalid MinLevel %q, must be INFO, WARN or THREAT", cfg.MinLevel)
	}

	return cfg, nil
}
