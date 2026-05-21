// ========================== BadBot detector ============================================
//   Detects known bad bots by matching User-Agent (and optionally Referer) against
//   community-curated blocklists managed by blocklist.Manager.
//
//   WHAT IS HERE:
//     BadBotDetector — Detector implementation; delegates matching to Matcher
//     Matcher        — interface satisfied by *blocklist.Manager (and test stubs)
//     NewBadBotDetector(cfg, mgr) — constructor; no goroutines started here
//     Detect()       — calls mgr.Match("badbot-ua") and optionally mgr.Match("badbot-ref")
//
//   WHAT IS NOT HERE:
//     Fetch logic, storage, goroutines — all moved to internal/core/blocklist.Manager
//     Pattern lists, refresh schedule — configured via top-level blocklist: in config.yaml
//
//   LIST NAMES (convention, see D4 — Flow #025):
//     "badbot-ua"  — User-Agent blocklist (mitchellkrogza plain_text, ~685 patterns)
//     "badbot-ref" — Referrer blocklist (mitchellkrogza plain_text, ~7108 patterns)
//     If a list is not loaded yet, Match returns false (graceful degradation).
//
//   Implemented: Flow #025, Task 4. Previous version: Flow #024, Task 4.

package detector

import (
	"strings"

	"github.com/mr-addams/nginx-sentinel/internal/core/parser"
	"github.com/mr-addams/nginx-sentinel/internal/sys/config"
)

// Matcher is satisfied by *blocklist.Manager and by test stubs.
// Defined here to avoid importing the blocklist package in detector tests.
type Matcher interface {
	Match(list string, text string) bool
}

// BadBotDetector matches incoming log entries against blocklist.Manager.
// No goroutines — all refresh and persistence is owned by the Manager.
// Thread-safe: Detect() only calls Matcher.Match() which is itself thread-safe.
type BadBotDetector struct {
	cfg config.BadBotConfig
	mgr Matcher
}

// NewBadBotDetector creates a detector backed by mgr.
// mgr must be non-nil; it is the caller's responsibility to keep it alive.
func NewBadBotDetector(cfg config.BadBotConfig, mgr Matcher) *BadBotDetector {
	return &BadBotDetector{cfg: cfg, mgr: mgr}
}

// Name returns the detector identifier used in threat log and metrics.
func (d *BadBotDetector) Name() string { return "badbot" }

// Detect checks UA and optionally Referer against the blocklists in Manager.
// Returns Score=0 when the list is not yet loaded (graceful degradation on startup).
func (d *BadBotDetector) Detect(_ IPView, entry *parser.LogEntry) DetectResult {
	if d.cfg.CheckUA {
		ua := strings.ToLower(entry.UserAgent)
		if ua != "" && ua != "-" && d.mgr.Match("badbot-ua", ua) {
			return DetectResult{
				Score:  d.cfg.Score,
				Module: "badbot",
				Reason: "ua-match",
			}
		}
	}

	if d.cfg.CheckReferrer && entry.Referer != "" && entry.Referer != "-" {
		ref := strings.ToLower(entry.Referer)
		if d.mgr.Match("badbot-ref", ref) {
			return DetectResult{
				Score:  d.cfg.Score,
				Module: "badbot",
				Reason: "ref-match",
			}
		}
	}

	return DetectResult{}
}
