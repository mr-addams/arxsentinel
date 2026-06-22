// ========================== Crawler detector ============================================
//   Detects sequential URL traversal by numeric pattern.
//   Indicator of an automated content scanner.
//
//   ALGORITHM:
//     1. For each path in RecentPaths extract (prefix, num) via numericSuffixRE:
//        /page/5     → prefix="/page/",  num=5
//        /product/42 → prefix="/product/", num=42
//     2. Group numbers by prefix.
//     3. If a group contains min_sequential consecutive integers → score.
//
//   WHY NUMERIC SEQUENCE:
//     Legitimate users rarely traverse 5+ pages in strict numeric order within
//     a short time window. /page/1→/page/2→...→/page/5 is an automation pattern.
//
//   LIMITATION:
//     Only the last 64 paths are analyzed (ring buffer in state.IPState).
//     Crawlers with windows > 64 unique URLs are not detected — caught by rate detector.
//
//   Params (DetectorConfig.Params):
//     min_sequential  int — consecutive numeric URLs needed to trigger (default: 5)
//     score           int — threat score on trigger (default: 20)
//
//   Registered as "crawler" via init().

package crawler

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"

	"github.com/mr-addams/arxsentinel/pkg/plugin"

	detector "github.com/mr-addams/arxsentinel/pkg/detector"
)

func init() {
	detector.Register("crawler", newCrawlerFactory)
}

// numericSuffixRE extracts (prefix, digits) from a URL path whose last segment is a pure number.
//
// `(.*/|/)` requires a "/" separator before the number, excluding slug-numbers like /api/v2.
// Match examples:
//
//	/page/5   → prefix="/page/",   num="5"
//	/items/12 → prefix="/items/",  num="12"
//	/5        → prefix="/",        num="5"
//
// Non-match: /api/v2 (/item5 — numeric suffix is not a standalone segment).
var numericSuffixRE = regexp.MustCompile(`^(.*/|/)(\d+)/?$`)

// crawlerDetector detects sequential numeric URL traversal.
type crawlerDetector struct {
	minSequential int
	score         int
}

// newCrawlerFactory creates a crawlerDetector from DetectorConfig.
func newCrawlerFactory(cfg detector.DetectorConfig, _ detector.SharedResources) (plugin.Detector, error) {
	return &crawlerDetector{
		minSequential: detector.GetInt(cfg, "min_sequential", 5),
		score:         detector.GetInt(cfg, "score", 20),
	}, nil
}

// Name returns the detector identifier.
func (d *crawlerDetector) Name() string { return "crawler" }

// Detect searches for numeric sequences in the IP's path history.
// Called from: pipeline.processEntries.
//
// Non-blocking.
func (d *crawlerDetector) Detect(sv plugin.IPView, _ *plugin.LogEntry) plugin.DetectResult {
	paths := sv.RecentPaths()
	if len(paths) < d.minSequential {
		return plugin.DetectResult{}
	}

	// Group numeric suffixes by URL prefix.
	groups := make(map[string][]int, len(paths))
	for _, p := range paths {
		prefix, num, ok := parseNumericPath(p)
		if !ok {
			continue
		}
		groups[prefix] = append(groups[prefix], num)
	}

	for prefix, nums := range groups {
		if hasConsecutiveSequence(nums, d.minSequential) {
			return plugin.DetectResult{
				Score:  d.score,
				Module: "crawler",
				Reason: fmt.Sprintf("crawler:seq=%s*%d", prefix, d.minSequential),
			}
		}
	}

	return plugin.DetectResult{}
}

// ========================== Helper functions ==========================================

// parseNumericPath extracts (prefix, num) from a URL with a numeric last segment.
func parseNumericPath(path string) (prefix string, num int, ok bool) {
	m := numericSuffixRE.FindStringSubmatch(path)
	if m == nil {
		return "", 0, false
	}
	n, err := strconv.Atoi(m[2])
	if err != nil {
		return "", 0, false
	}
	return m[1], n, true
}

// hasConsecutiveSequence returns true when nums contains minLen consecutive integers
// (after deduplication). Identical numbers from repeated requests are not counted
// as separate steps.
func hasConsecutiveSequence(nums []int, minLen int) bool {
	if len(nums) == 0 || minLen <= 0 {
		return false
	}
	if len(nums) < minLen {
		return false
	}

	sort.Ints(nums)

	// Deduplicate: /page/5 visited twice counts as one step, not two.
	// make instead of nums[:1] isolates the new slice from the original backing array.
	uniq := make([]int, 1, len(nums))
	uniq[0] = nums[0]
	for _, n := range nums[1:] {
		if n != uniq[len(uniq)-1] {
			uniq = append(uniq, n)
		}
	}
	if len(uniq) < minLen {
		return false
	}

	consec := 1
	for i := 1; i < len(uniq); i++ {
		if uniq[i] == uniq[i-1]+1 {
			consec++
			if consec >= minLen {
				return true
			}
		} else {
			consec = 1
		}
	}

	// The last run may not have reached minLen inside the loop.
	return consec >= minLen
}
