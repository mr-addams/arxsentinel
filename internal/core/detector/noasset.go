// ========================== NoAsset detector ============================================
//   Detects bots that request HTML pages without loading static assets (CSS/JS/images).
//   A legitimate browser always loads page resources — a bot does not.
//
//   WHAT IS HERE:
//     - NoAssetDetector — struct with parameters and a pre-built extension set
//     - NewNoAssetDetector(cfg) — initialization, builds the assetExts map
//     - Detect() — counts pages and assets in RecentPaths, checks ratio
//
//   ALGORITHM:
//     For each path in RecentPaths determine its type:
//       - asset: extension is in AssetExtensions (.css, .js, .png, ...)
//       - page:  everything else (no extension, .html, .php, .asp, ...)
//     If pageCount >= MinPageRequests && assetCount/total < AssetRatioThreshold → score.
//
//   WHY EXTENSION AND NOT CONTENT-TYPE:
//     LogEntry does not contain the response Content-Type — nginx writes only request lines.
//     Path extension is a reliable proxy: a browser loads href=".css" → path has .css.
//     Exception: SPAs (React/Vue) — everything via /api/ without extensions. The detector may
//     produce false positives for SPA bots. Lowering AssetRatioThreshold reduces false noise.
//
//   DATA DEPENDENCY:
//     RecentPaths — ring buffer of the last 64 paths (state.pathBuf).
//     With minPageRequests=3 and buffer=64, the first pages of an IP are already
//     accumulated by the time the detector fires.
//
//   Implemented: Task 6.3.

package detector

import (
	"fmt"
	"path"
	"strings"

	"github.com/mr-addams/nginx-sentinel/internal/core/parser"
	"github.com/mr-addams/nginx-sentinel/internal/sys/config"
)

// ========================== NoAssetDetector ===========================================

// NoAssetDetector detects bots that do not load static page resources.
type NoAssetDetector struct {
	enabled             bool
	minPageRequests     int
	assetRatioThreshold float64
	score               int
	assetExts           map[string]struct{} // set of static resource extensions
}

// NewNoAssetDetector creates a NoAssetDetector from config.
// Builds the assetExts map once — O(1) lookup on the hot path instead of O(n) over a slice.
// Called from main.go on startup and SIGHUP.
func NewNoAssetDetector(cfg config.NoAssetConfig) *NoAssetDetector {
	exts := make(map[string]struct{}, len(cfg.AssetExtensions))
	for _, ext := range cfg.AssetExtensions {
		exts[strings.ToLower(ext)] = struct{}{}
	}
	return &NoAssetDetector{
		enabled:             cfg.Enabled,
		minPageRequests:     cfg.MinPageRequests,
		assetRatioThreshold: cfg.AssetRatioThreshold,
		score:               cfg.Score,
		assetExts:           exts,
	}
}

// Name returns the detector identifier.
func (d *NoAssetDetector) Name() string { return "noasset" }

// Detect analyzes the page-to-asset ratio in the IP request history.
//
// Does not trigger if pageCount < minPageRequests — the IP may have just started browsing,
// statistics are not yet representative.
func (d *NoAssetDetector) Detect(sv IPView, entry *parser.LogEntry) DetectResult {
	if !d.enabled {
		return DetectResult{}
	}

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
		return DetectResult{}
	}

	total := pageCount + assetCount
	// total > 0 is guaranteed: pageCount >= minPageRequests > 0.
	assetRatio := float64(assetCount) / float64(total)
	if assetRatio >= d.assetRatioThreshold {
		return DetectResult{}
	}

	return DetectResult{
		Score:  d.score,
		Module: "noasset",
		Reason: fmt.Sprintf("noasset:pages=%d,assets=%d,ratio=%.0f%%",
			pageCount, assetCount, assetRatio*100),
	}
}

// isAsset returns true if the path ends with a static resource extension.
// Uses path.Ext (forward-slash semantics, not filepath.Ext) for URL paths.
func (d *NoAssetDetector) isAsset(urlPath string) bool {
	// Strip query string if somehow present in the path (defensive)
	if idx := strings.IndexByte(urlPath, '?'); idx >= 0 {
		urlPath = urlPath[:idx]
	}
	ext := strings.ToLower(path.Ext(urlPath))
	_, ok := d.assetExts[ext]
	return ok
}
