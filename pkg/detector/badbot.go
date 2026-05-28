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

package detector

import (
	"strings"

	"github.com/mr-addams/arxsentinel/pkg/plugin"
)

func init() {
	Register("badbot", newBadBotFactory)
}

// badBotDetector matches incoming log entries against a blocklist Matcher.
// Thread-safe: Detect() only calls Matcher.Match() which is itself thread-safe.
type badBotDetector struct {
	mgr           Matcher
	score         int
	checkUA       bool
	checkReferrer bool
}

// newBadBotFactory creates a badBotDetector from DetectorConfig.
//
// If shared is nil or shared.Blocklist() returns nil, the detector is created
// with a noopMatcher — it starts up cleanly and becomes active once the blocklist
// is configured and a Matcher is provided.
func newBadBotFactory(cfg DetectorConfig, shared SharedResources) (plugin.Detector, error) {
	var mgr Matcher = noopMatcher{}
	if shared != nil {
		if bl := shared.Blocklist(); bl != nil {
			mgr = bl
		}
	}

	return &badBotDetector{
		mgr:           mgr,
		score:         getInt(cfg.Params, "score", 60),
		checkUA:       getBool(cfg.Params, "check_ua", true),
		checkReferrer: getBool(cfg.Params, "check_referrer", false),
	}, nil
}

// Name returns the detector identifier.
func (d *badBotDetector) Name() string { return "badbot" }

// Detect checks UA and optionally Referer against the blocklist.
// Returns Score=0 when the list is not yet loaded (graceful degradation on startup).
// Reason includes the matched pattern (e.g., "ua=googlebot") for operational diagnostics.
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
