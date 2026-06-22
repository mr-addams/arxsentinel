// ====== Module: cloudflare — config ===============================================
//   Configuration for Cloudflare API communication — parses from YAML/JSON
//   with validation of required fields and time.Duration handling.
//
//   WHAT IS HERE:
//     Config struct with json/yaml tags, parseConfig function
//
//   WHAT IS NOT HERE:
//     HTTP client implementation (client.go), executor logic (executor.go), registration (register.go)

package cloudflare

import (
	// ── Group 1: standard library ──
	"encoding/json"
	"fmt"
	"strings"
	"time"

	// ── Group 2: project ──
	"github.com/mr-addams/arx-core/pkg/logger"
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
	// to identify the list during updates; defaults to "arxsentinel_blocklist".
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
	// CommentExtra is appended to the ban comment after a space separator.
	// YAML: cloudflare.comment_extra, default "" — optional suffix for CF ban comment.
	// Format: "sentinel-<id> <extra>". Max 50 chars (truncated if longer).
	// Consumer: executor.buildComment
	CommentExtra string `json:"comment_extra" yaml:"comment_extra"`
	// APIBaseURL overrides the default Cloudflare API endpoint. Intended for
	// integration tests against a local CF API mock server.
	APIBaseURL string `json:"api_base_url" yaml:"api_base_url"`
}

// ++++++++++++++++++++++++++ Defaults ++++++++++++++++++++++++++++++++++++++++

// DefaultConfig returns a Config with all defaults populated.
func DefaultConfig() Config {
	return Config{
		ListName:      "arxsentinel_blocklist",
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
func parseConfig(raw map[string]interface{}, log logger.Logger) (Config, error) {
	// nil-logger guard mirrors Decision 2: the constructor still works when a
	// caller passes nil — we use the no-op default rather than touching the
	// pre-1.2 utils.Log global.
	if log == nil {
		log = logger.Nop
	}

	// ---- Default values ----
	cfg := Config{
		ListName:      "arxsentinel_blocklist",
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

	// ---- Comment_extra: read before JSON round-trip ----
	if v, ok := rawCopy["comment_extra"].(string); ok {
		delete(rawCopy, "comment_extra")
		cfg.CommentExtra = strings.TrimSpace(v)
		cfg.CommentExtra = strings.Map(func(r rune) rune {
			if r == '\n' || r == '\t' || r == '\r' {
				return ' '
			}
			return r
		}, cfg.CommentExtra)
		if len(cfg.CommentExtra) > 50 {
			// Log warning so operators notice their comment_extra was silently truncated.
			log.Log("CONFIG", fmt.Sprintf("cloudflare: comment_extra truncated from %d to 50 chars", len(cfg.CommentExtra)), logger.LevelWarning)
			cfg.CommentExtra = cfg.CommentExtra[:50]
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
