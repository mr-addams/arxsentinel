// ========================== BadBot detector ============================================
//   Detects known bad bots by matching User-Agent (and optionally Referer) against
//   community-curated blocklists via the Matcher interface.
//
//   WHAT IS HERE:
//     badBotDetector — Detector implementation; delegates matching to Matcher
//     newBadBotFactory — reads params, obtains Matcher from SharedResources
//     Detect — calls Matcher.Match("badbot-ua") and optionally "badbot-ref"
//
//   WHAT IS NOT HERE:
//     Fetch logic, storage, goroutines — owned by *blocklist.Manager (internal/)
//     Pattern lists, refresh schedule — configured via blocklist: in config.yaml
//
//   LIST NAMES (convention, see D4 — Flow #025):
//     "badbot-ua"  — User-Agent blocklist
//     "badbot-ref" — Referrer blocklist
//     If a list is not loaded yet, Match returns false (graceful degradation).
//     These list names MUST match blocklist.lists[].name values in config.yaml.
//     If the names diverge, the detector silently finds no patterns — no error is returned.
//
//   SharedResources:
//     Blocklist() returns the Matcher satisfied by *blocklist.Manager.
//     If nil → noopMatcher is used (detector becomes a no-op, not an error).
//
//   Params (DetectorConfig.Params):
//     check_ua       bool — check User-Agent against blocklist (default: true)
//     check_referrer bool — check Referer against blocklist (default: false)
//     score          int  — threat score on match (default: 60)
//
//   Registered as "badbot" via init().

package badbot

import (
	"strings"

	detector "github.com/mr-addams/arxsentinel/pkg/detector"
	"github.com/mr-addams/arx-core/pkg/plugin"
)

func init() {
	detector.Register("badbot", newBadBotFactory)
}

// badBotDetector matches incoming log entries against a blocklist Matcher.
// Thread-safe: Detect() only calls Matcher.Match() which is itself thread-safe.
type badBotDetector struct {
	mgr           detector.Matcher
	score         int
	checkUA       bool
	checkReferrer bool
}

// newBadBotFactory creates a badBotDetector from DetectorConfig.
//
// If shared is nil or shared.Blocklist() returns nil, the detector is created
// with a noopMatcher — it starts up cleanly and becomes active once the blocklist
// is configured and a Matcher is provided.
func newBadBotFactory(cfg detector.DetectorConfig, shared detector.SharedResources) (plugin.Detector, error) {
	var mgr detector.Matcher = noopMatcher{}
	if shared != nil {
		if bl := shared.Blocklist(); bl != nil {
			mgr = bl
		}
	}

	return &badBotDetector{
		mgr:           mgr,
		score:         detector.GetInt(cfg, "score", 60),
		checkUA:       detector.GetBool(cfg, "check_ua", true),
		checkReferrer: detector.GetBool(cfg, "check_referrer", false),
	}, nil
}

// Name returns the detector identifier.
func (d *badBotDetector) Name() string { return "badbot" }

// Detect checks UA and optionally Referer against the blocklist.
// Returns Score=0 when the list is not yet loaded (graceful degradation on startup).
// Reason includes the matched pattern (e.g., "ua=googlebot") for operational diagnostics.
// Called from: pipeline.processEntries.
//
// Non-blocking.
func (d *badBotDetector) Detect(_ plugin.IPView, entry *plugin.LogEntry) plugin.DetectResult {
	if d.checkUA {
		ua := strings.ToLower(entry.UserAgent)
		if ua != "" && ua != "-" {
			if pattern, ok := d.mgr.MatchResult("badbot-ua", ua); ok {
				return plugin.DetectResult{
					Score:  d.score,
					Module: "badbot",
					Reason: "ua=" + pattern,
				}
			}
		}
	}

	if d.checkReferrer {
		ref := strings.ToLower(entry.Referer)
		if ref != "" && ref != "-" {
			if pattern, ok := d.mgr.MatchResult("badbot-ref", ref); ok {
				return plugin.DetectResult{
					Score:  d.score,
					Module: "badbot",
					Reason: "ref=" + pattern,
				}
			}
		}
	}

	return plugin.DetectResult{}
}

// noopMatcher is a Matcher that never matches.
// Used when SharedResources is nil or returns a nil Blocklist —
// the detector remains functional but cannot match any blocklist entry.
type noopMatcher struct{}

func (noopMatcher) Match(string, string) bool { return false }

func (noopMatcher) MatchResult(string, string) (string, bool) { return "", false }
