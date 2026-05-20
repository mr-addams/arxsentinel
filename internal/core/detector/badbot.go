// ========================== BadBot detector ============================================
//   Detects known bad bots by matching User-Agent (and optionally Referer) against
//   community-curated blocklists fetched from upstream sources.
//
//   WHAT IS HERE:
//     BadBotDetector  — Detector implementation; uses Aho-Corasick for O(text_len) matching
//     NewBadBotDetector(ctx, cfg) — constructor; starts the background refresh goroutine
//     Detect()        — matches UA / Referer against in-memory automata
//     run(ctx)        — refresh loop: load from store, fetch from network, rebuild automata
//     fetchAndRebuild — fetches all configured sources and rebuilds automata atomically
//     parseList       — parses plain-text format (one pattern per line, # comments skipped)
//     parseNginxMap   — fallback parser for nginx map format (extracts names from \b...\b)
//
//   MATCHING ALGORITHM:
//     Aho-Corasick (Double-Array Trie via github.com/rrethy/ahocorasick).
//     Build once on load: O(total_pattern_chars). Search per request: O(text_len).
//     685 UA patterns → ~200 KB automaton. 7108 referrer patterns → ~1.8 MB.
//
//   GOROUTINE LIFECYCLE:
//     NewBadBotDetector starts one goroutine bound to ctx.
//     ctx is cancelled by main.go's newBadBotDetector factory on SIGHUP,
//     stopping the old goroutine before creating a new detector instance.
//
//   DATA SOURCES (default):
//     mitchellkrogza/nginx-ultimate-bad-bot-blocker (MIT License)
//     Plain-text lists: _generator_lists/bad-user-agents.list
//                       _generator_lists/bad-referrer-words.list
//
//   Implemented: Flow #24, Task 4.

package detector

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/rrethy/ahocorasick"

	"github.com/mr-addams/nginx-sentinel/internal/core/parser"
	"github.com/mr-addams/nginx-sentinel/internal/sys/config"
	"github.com/mr-addams/nginx-sentinel/internal/sys/utils"
)

// nginxPatternRe extracts the bot/referrer name from nginx map entries like:
//
//	"~*(?:\b)AhrefsBot(?:\b)"    3;
var nginxPatternRe = regexp.MustCompile(`\(\?:\\b\)(.+?)\(\?:\\b\)`)

// httpClient is shared across all blocklist fetches.
// Explicit 30s timeout prevents goroutine hangs on slow or unresponsive upstream sources.
// http.DefaultClient has Timeout=0 (infinite) which would block the refresh goroutine forever.
var httpClient = &http.Client{Timeout: 30 * time.Second}

// fetchSizeLimit caps the response body read — protects against memory exhaustion
// if an upstream source sends a response larger than any reasonable blocklist.
const fetchSizeLimit = 10 << 20 // 10 MB

// ========================== BadBotDetector ============================================

type BadBotDetector struct {
	cfg   config.BadBotConfig
	store PatternStore

	mu         sync.RWMutex
	uaMatcher  *ahocorasick.Matcher // nil until first successful load
	refMatcher *ahocorasick.Matcher // nil when check_referrer=false or not yet loaded
}

// NewBadBotDetector creates a detector and starts the background refresh goroutine.
// Returns immediately; automata may be nil until the first successful fetch.
func NewBadBotDetector(ctx context.Context, cfg config.BadBotConfig) *BadBotDetector {
	store, err := newPatternStore(cfg.Storage)
	if err != nil {
		utils.Log("BADBOT", fmt.Sprintf("storage open error (%s): %v — falling back to memory store", cfg.Storage, err), "warn")
		store = &MemoryStore{}
	}

	d := &BadBotDetector{cfg: cfg, store: store}
	go d.run(ctx)
	return d
}

// Name returns the detector identifier used in threat log and metrics.
func (d *BadBotDetector) Name() string { return "badbot" }

// Detect checks User-Agent (and optionally Referer) against the loaded automata.
// Returns Score=0 when automata are not yet built (graceful degradation on startup).
func (d *BadBotDetector) Detect(_ IPView, entry *parser.LogEntry) DetectResult {
	d.mu.RLock()
	uaM, refM := d.uaMatcher, d.refMatcher
	d.mu.RUnlock()

	if uaM == nil && refM == nil {
		return DetectResult{}
	}

	ua := strings.ToLower(entry.UserAgent)
	if uaM != nil && ua != "" && ua != "-" {
		if matches := uaM.FindAllString(ua); len(matches) > 0 {
			return DetectResult{
				Score:  d.cfg.Score,
				Module: "badbot",
				Reason: "ua:" + string(matches[0].Word),
			}
		}
	}

	if refM != nil && entry.Referer != "" && entry.Referer != "-" {
		ref := strings.ToLower(entry.Referer)
		if matches := refM.FindAllString(ref); len(matches) > 0 {
			return DetectResult{
				Score:  d.cfg.Score,
				Module: "badbot",
				Reason: "ref:" + string(matches[0].Word),
			}
		}
	}

	return DetectResult{}
}

// ── Background refresh ────────────────────────────────────────────────────────────────

// run is the background goroutine: loads cached patterns, fetches from network, then
// refreshes on schedule. Exits when ctx is cancelled.
func (d *BadBotDetector) run(ctx context.Context) {
	// Fast path: load previously persisted patterns before the first network fetch.
	// With bbolt this makes the automaton available within milliseconds on restart.
	if ua, ref, err := d.store.Load(); err == nil && (len(ua) > 0 || len(ref) > 0) {
		d.rebuild(ua, ref)
		utils.Log("BADBOT", fmt.Sprintf("loaded %d UA + %d referrer patterns from store", len(ua), len(ref)), "info")
	}

	d.fetchAndRebuild(ctx)

	ticker := time.NewTicker(time.Duration(d.cfg.RefreshInterval))
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			d.store.Close()
			return
		case <-ticker.C:
			d.fetchAndRebuild(ctx)
		}
	}
}

// fetchAndRebuild fetches all configured sources and rebuilds the automata.
// Each source's UA and Ref lists are fetched independently — an error on one
// does not prevent the others from contributing patterns.
// If ALL fetches fail (zero patterns loaded from any source), the rebuild is
// skipped and the previous automata remain active (graceful degradation).
func (d *BadBotDetector) fetchAndRebuild(ctx context.Context) {
	var allUA, allRef []string
	seenUA := make(map[string]struct{})
	seenRef := make(map[string]struct{})
	anyLoaded := false

	for _, src := range d.cfg.Sources {
		if d.cfg.CheckUA && src.UAURL != "" {
			patterns, err := fetchList(ctx, src.UAURL)
			if err != nil {
				utils.Log("BADBOT", fmt.Sprintf("source %q UA fetch error: %v — skipping source", src.Name, err), "warn")
			} else {
				for _, p := range patterns {
					if _, dup := seenUA[p]; !dup {
						seenUA[p] = struct{}{}
						allUA = append(allUA, p)
					}
				}
				utils.Log("BADBOT", fmt.Sprintf("source %q: fetched %d UA patterns", src.Name, len(patterns)), "info")
				anyLoaded = true
			}
		}

		if d.cfg.CheckReferrer && src.RefURL != "" {
			patterns, err := fetchList(ctx, src.RefURL)
			if err != nil {
				utils.Log("BADBOT", fmt.Sprintf("source %q referrer fetch error: %v — skipping source", src.Name, err), "warn")
			} else {
				for _, p := range patterns {
					if _, dup := seenRef[p]; !dup {
						seenRef[p] = struct{}{}
						allRef = append(allRef, p)
					}
				}
				utils.Log("BADBOT", fmt.Sprintf("source %q: fetched %d referrer patterns", src.Name, len(patterns)), "info")
				anyLoaded = true
			}
		}
	}

	if !anyLoaded {
		utils.Log("BADBOT", "all sources failed — keeping previous patterns", "warn")
		return
	}

	if err := d.store.Save(allUA, allRef); err != nil {
		utils.Log("BADBOT", "store save error: "+err.Error(), "warn")
	}

	d.rebuild(allUA, allRef)
}

// rebuild compiles new Aho-Corasick automata and swaps them atomically.
func (d *BadBotDetector) rebuild(ua, ref []string) {
	var uaM, refM *ahocorasick.Matcher
	if len(ua) > 0 {
		uaM = ahocorasick.CompileStrings(ua)
	}
	if d.cfg.CheckReferrer && len(ref) > 0 {
		refM = ahocorasick.CompileStrings(ref)
	}
	d.mu.Lock()
	d.uaMatcher, d.refMatcher = uaM, refM
	d.mu.Unlock()
}

// ── Fetch and parse ───────────────────────────────────────────────────────────────────

// fetchList downloads a pattern list from url and parses it.
// Tries plain-text format first; falls back to nginx map format on parse failure.
func fetchList(ctx context.Context, url string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, fetchSizeLimit))
	if err != nil {
		return nil, err
	}

	patterns := parseList(data)
	if len(patterns) == 0 {
		// Try nginx map format as fallback (e.g. globalblacklist.conf).
		patterns = parseNginxMap(data)
	}
	return patterns, nil
}

// parseList parses plain-text format: one pattern per line, # lines skipped.
// Patterns are lowercased for case-insensitive Aho-Corasick matching.
func parseList(data []byte) []string {
	var result []string
	for _, line := range bytes.Split(data, []byte("\n")) {
		s := strings.TrimSpace(string(line))
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		result = append(result, strings.ToLower(s))
	}
	return result
}

// parseNginxMap extracts pattern names from nginx map format:
//
//	"~*(?:\b)AhrefsBot(?:\b)"    3;
//
// Used as a fallback when the plain-text generator list is unavailable.
func parseNginxMap(data []byte) []string {
	matches := nginxPatternRe.FindAllSubmatch(data, -1)
	result := make([]string, 0, len(matches))
	for _, m := range matches {
		if len(m) > 1 {
			result = append(result, strings.ToLower(string(m[1])))
		}
	}
	return result
}
