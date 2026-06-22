// ========================== NoAsset detector ============================================
//   Detects bots that request HTML pages without loading static assets (CSS/JS/images).
//   A legitimate browser always loads page resources — a bot does not.
//
//   ALGORITHM:
//     For each path in RecentPaths:
//       asset: extension in asset_extensions set
//       page:  everything else
//     If pageCount >= min_page_requests && assetCount/total < asset_ratio_threshold → score.
//
//   WHY EXTENSION AND NOT CONTENT-TYPE:
//     LogEntry has no response Content-Type — nginx writes only request lines.
//     Path extension is a reliable proxy for asset vs. page distinction.
//
//   Params (DetectorConfig.Params):
//     min_page_requests      int      — min pages before triggering (default: 3)
//     asset_ratio_threshold  float64  — minimum asset ratio for clean traffic (default: 0.1)
//     score                  int      — threat score on trigger (default: 20)
//     asset_extensions       []string — extensions treated as assets (default: see below)
//
//   Registered as "noasset" via init().

package noasset

import (
	"fmt"
	"path"
	"strings"

	detector "github.com/mr-addams/arx-core/pkg/detector"
	"github.com/mr-addams/arx-core/pkg/plugin"
)

func init() {
	detector.Register("noasset", newNoAssetFactory)
}

// defaultAssetExtensions is the built-in list of static resource extensions.
var defaultAssetExtensions = []string{
	".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg",
	".woff", ".woff2", ".ttf", ".ico", ".webp",
}

// noAssetDetector detects bots that do not load static page resources.
type noAssetDetector struct {
	minPageRequests     int
	assetRatioThreshold float64
	score               int
	assetExts           map[string]struct{} // O(1) extension lookup
}

// newNoAssetFactory creates a noAssetDetector from DetectorConfig.
func newNoAssetFactory(cfg detector.DetectorConfig, _ detector.SharedResources) (plugin.Detector, error) {
	minPageRequests := detector.GetInt(cfg, "min_page_requests", 3)
	assetRatioThreshold := detector.GetFloat64(cfg, "asset_ratio_threshold", 0.1)
	score := detector.GetInt(cfg, "score", 20)
	exts := detector.GetStrings(cfg, "asset_extensions", defaultAssetExtensions)

	// Build set once — O(1) lookup on the hot path instead of O(n) over slice.
	extSet := make(map[string]struct{}, len(exts))
	for _, ext := range exts {
		extSet[strings.ToLower(ext)] = struct{}{}
	}

	return &noAssetDetector{
		minPageRequests:     minPageRequests,
		assetRatioThreshold: assetRatioThreshold,
		score:               score,
		assetExts:           extSet,
	}, nil
}

// Name returns the detector identifier.
func (d *noAssetDetector) Name() string { return "noasset" }

// Detect analyzes the page-to-asset ratio in the IP request history.
//
// Does not trigger if pageCount < minPageRequests — the IP may have just started
// browsing; statistics are not yet representative.
// Called from: pipeline.processEntries.
//
// Non-blocking.
func (d *noAssetDetector) Detect(sv plugin.IPView, _ *plugin.LogEntry) plugin.DetectResult {
	paths := sv.RecentPaths()

	var pageCount, assetCount int
	for _, p := range paths {
		if d.isAsset(p) {
			assetCount++
		} else {
			pageCount++
		}
	}

	if pageCount < d.minPageRequests {
		return plugin.DetectResult{}
	}

	total := pageCount + assetCount
	// total > 0 is guaranteed: pageCount >= minPageRequests > 0.
	assetRatio := float64(assetCount) / float64(total)
	if assetRatio >= d.assetRatioThreshold {
		return plugin.DetectResult{}
	}

	return plugin.DetectResult{
		Score:  d.score,
		Module: "noasset",
		Reason: fmt.Sprintf("noasset:pages=%d,assets=%d,ratio=%.0f%%",
			pageCount, assetCount, assetRatio*100),
	}
}

// isAsset returns true if the path ends with a static resource extension.
// Uses path.Ext (forward-slash semantics) for URL paths.
func (d *noAssetDetector) isAsset(urlPath string) bool {
	// Strip query string if somehow present in the path (defensive).
	if idx := strings.IndexByte(urlPath, '?'); idx >= 0 {
		urlPath = urlPath[:idx]
	}
	ext := strings.ToLower(path.Ext(urlPath))
	_, ok := d.assetExts[ext]
	return ok
}
