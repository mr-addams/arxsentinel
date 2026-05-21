// ========================== Probe detector ==============================================
//   Detects requests to sensitive paths: .env, .git, wp-config, aws-exports, etc.
//   A single matched path = a fixed score penalty for the IP.
//
//   WHAT IS HERE:
//     - ProbeDetector — struct with a pre-built path set
//     - NewProbeDetector(cfg) — initialization from config
//     - Detect() — O(1) exact-match + linear prefix-match
//
//   ALGORITHM:
//     1. Exact match in map[string]struct{} — O(1), covers static paths (.env, wp-config.php)
//     2. Prefix match — catches /wp-admin/page.php, /actuator/env, etc.
//     Paths ending with "/" in config → prefix check.
//     All others → exact-match map.
//
//   WHY MAP AND NOT SLICE:
//     map[string]struct{} for exact-match: O(1) lookup, easy to extend —
//     adding a new path to config requires no code changes.
//
//   Implemented: Task 4.1.

package detector

import (
	"strings"

	"github.com/mr-addams/arxsentinel/internal/core/parser"
	"github.com/mr-addams/arxsentinel/internal/sys/config"
)

// ========================== ProbeDetector =============================================

// ProbeDetector detects requests to sensitive paths.
//
// Lifecycle:
//   nil              → before NewProbeDetector is called
//   *ProbeDetector   → after NewProbeDetector, used for the daemon's entire lifetime
//   rebuild          → on SIGHUP (Task 7.1) — a new instance is created from the new config
type ProbeDetector struct {
	score    int
	pathSet  map[string]struct{} // exact-match paths: O(1) lookup
	prefixes []string            // prefix paths (ending with "/"): catches any sub-path
	enabled  bool
}

// NewProbeDetector creates a ProbeDetector from config.
// Splits paths: ending with "/" → prefixes (prefix-match), others → pathSet (exact-match).
// Called from main.go on startup and SIGHUP.
func NewProbeDetector(cfg config.ProbeConfig) *ProbeDetector {
	pathSet := make(map[string]struct{}, len(cfg.Paths))
	var prefixes []string

	for _, p := range cfg.Paths {
		if strings.HasSuffix(p, "/") {
			// /wp-admin/, /actuator/ — prefix check catches any sub-path
			prefixes = append(prefixes, p)
		} else {
			pathSet[p] = struct{}{}
		}
	}

	return &ProbeDetector{
		score:    cfg.Score,
		pathSet:  pathSet,
		prefixes: prefixes,
		enabled:  cfg.Enabled,
	}
}

// Name returns the detector identifier for logs and threat records.
func (d *ProbeDetector) Name() string { return "probe" }

// Detect checks the request path against sensitive paths.
//
// Order: exact match → prefix match.
// Exact match first: O(1) and covers the majority of static sensitive paths.
// Prefix match second: O(n) over prefix count, catches sub-paths (/wp-admin/login.php).
//
// entry.Path is already without query string — the parser split it into Path + Query.
func (d *ProbeDetector) Detect(sv IPView, entry *parser.LogEntry) DetectResult {
	if !d.enabled {
		return DetectResult{}
	}

	path := entry.Path

	// ── Exact match ───────────────────────────────────────────────────────────────────
	if _, ok := d.pathSet[path]; ok {
		return DetectResult{
			Score:  d.score,
			Module: "probe",
			Reason: "probe:" + path,
		}
	}

	// ── Prefix match ──────────────────────────────────────────────────────────────────
	// /wp-admin/ in config → triggers on /wp-admin/options-general.php, /wp-admin/, etc.
	for _, prefix := range d.prefixes {
		if strings.HasPrefix(path, prefix) {
			return DetectResult{
				Score:  d.score,
				Module: "probe",
				Reason: "probe:" + path,
			}
		}
	}

	return DetectResult{}
}
