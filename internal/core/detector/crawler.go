// ========================== Crawler detector ============================================
//   Detects sequential URL traversal by numeric pattern.
//   Indicator of an automated content scanner.
//
//   WHAT IS HERE:
//     - CrawlerDetector — struct with parameters from config
//     - NewCrawlerDetector(cfg) — initialization
//     - Detect() — searches for numeric sequences in RecentPaths
//
//   ALGORITHM:
//     1. For each path in RecentPaths extract (prefix, num) via numericSuffixRE:
//        /page/5       → prefix="/page/",  num=5
//        /product/42   → prefix="/product/", num=42
//        /archive/2024 → prefix="/archive/", num=2024
//     2. Group numbers by prefix.
//     3. If a group contains a sequence of MinSequential consecutive integers
//        (after deduplication and sorting) → score += Score.
//
//   WHY NUMERIC SEQUENCE:
//     Legitimate users, unlike crawlers, do not traverse pages in strict
//     numeric order. /page/1 → /page/2 → /page/3 → /page/4 → /page/5 in a short
//     time is an automation pattern, not organic browsing.
//     MinSequential=5 reduces false positives: a user rarely browses
//     5+ pages consecutively within the same numeric range.
//
//   LIMITATION:
//     Only the last 64 paths are analyzed (ring buffer pathBuf in IPState).
//     A crawler with a window > 64 unique URLs is not detected — acceptable,
//     since such traffic will be caught by RateDetector.
//
//   Implemented: Task 6.2.

package detector

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"

	"github.com/mr-addams/nginx-sentinel/internal/core/parser"
	"github.com/mr-addams/nginx-sentinel/internal/sys/config"
)

// numericSuffixRE extracts (prefix, digits) from a URL path where the LAST segment is a pure number.
//
// Pattern: `(.*/|/)` requires a `/` separator immediately before the number,
// which excludes slug-numbers like `/api/v2` or `/item5`.
// Match examples:
//
//	/page/5    → prefix="/page/",    num="5"
//	/items/12  → prefix="/items/",   num="12"
//	/5         → prefix="/",         num="5"
//
// Non-match examples (slug-numbers — not a standalone segment):
//
//	/api/v2    → no match (v2 is not a standalone numeric segment)
//	/item5     → no match (5 is a slug suffix, not a standalone segment)
//	/foo       → no match (no numeric segments)
var numericSuffixRE = regexp.MustCompile(`^(.*/|/)(\d+)/?$`)

// ========================== CrawlerDetector ===========================================

// CrawlerDetector detects sequential numeric URL traversal.
type CrawlerDetector struct {
	enabled       bool
	minSequential int
	score         int
}

// NewCrawlerDetector creates a CrawlerDetector from config.
// Called from main.go on startup and SIGHUP.
func NewCrawlerDetector(cfg config.CrawlerConfig) *CrawlerDetector {
	return &CrawlerDetector{
		enabled:       cfg.Enabled,
		minSequential: cfg.MinSequential,
		score:         cfg.Score,
	}
}

// Name returns the detector identifier.
func (d *CrawlerDetector) Name() string { return "crawler" }

// Detect searches for numeric sequences in the IP's path history.
//
// Called on every log line — the pattern search only runs when
// RecentPaths contains enough paths (>= MinSequential).
func (d *CrawlerDetector) Detect(sv IPView, entry *parser.LogEntry) DetectResult {
	if !d.enabled {
		return DetectResult{}
	}

	paths := sv.RecentPaths()
	if len(paths) < d.minSequential {
		return DetectResult{}
	}

	// Group numeric suffixes by prefix.
	// map[prefix][]int — list of numbers for each URL template.
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
			return DetectResult{
				Score:  d.score,
				Module: "crawler",
				Reason: fmt.Sprintf("crawler:seq=%s*%d", prefix, d.minSequential),
			}
		}
	}

	return DetectResult{}
}

// ========================== Helper functions ==========================================

// parseNumericPath extracts (prefix, num) from a URL path with a numeric suffix.
// Returns ok=false if the path contains no numeric suffix.
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

// hasConsecutiveSequence checks whether a slice contains a run of minLen consecutive
// integers (with deduplication applied before the check).
func hasConsecutiveSequence(nums []int, minLen int) bool {
	// minLen <= 0 is technically invalid; guard prevents panic below (nums[:1] on empty slice).
	if len(nums) == 0 || minLen <= 0 {
		return false
	}
	if len(nums) < minLen {
		return false
	}

	sort.Ints(nums)

	// Deduplication: identical numbers (repeated requests to the same URL) do not count
	// as separate steps in the sequence.
	// make instead of nums[:1]: isolates the slice from the original array — append in the loop
	// does not modify nums beyond uniq.
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

	// The last run may not have reached minLen inside the loop (including a single element with minLen=1).
	return consec >= minLen
}
