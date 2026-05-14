//go:build e2e

// ========================== E2E test — Task 5.4 ========================================
//   Runs .reference/example.access.log through the real pipeline without TailReader
//   and without whitelist/DNS. Verifies that known malicious IPs appear in the threat log
//   and that the line format is compatible with Fail2Ban.
//
//   Run: go test -run TestE2E -tags e2e -v .
//
//   NOT included in regular go test ./...:
//     whitelist/DNS is not needed — the test checks detectors only;
//     the e2e build tag isolates it from CI.

package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/mr-addams/nginx-sentinel/internal/core/output"
	"github.com/mr-addams/nginx-sentinel/internal/core/parser"
	"github.com/mr-addams/nginx-sentinel/internal/core/scorer"
	"github.com/mr-addams/nginx-sentinel/internal/core/state"
	"github.com/mr-addams/nginx-sentinel/internal/sys/config"
)

// fail2banRE — regexp matching the full structure of a threat-log line.
// Reproduces the failregex from deploy/fail2ban/filter.d/nginx-sentinel.conf
// and additionally checks for modules= and reason= — format regressions are caught immediately.
// modules=\S* (not \S+): the field may be empty when score carries over with no new detectors.
var fail2banRE = regexp.MustCompile(`(WARN|THREAT)\s+\S+\s+score=\d+\s+modules=\S*\s+reason=`)

func TestE2E(t *testing.T) {
	// ── Config: Go defaults, no config file ──────────────────────────────────────────────
	// LoadConfig("") → os.ReadFile("") → ENOENT → returns defaultConfig() without error.
	cfg, err := config.LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	// ── Pipeline: tracker + scorer with 7 detectors ──────────────────────────────────
	// logFn is a no-op to avoid cluttering the test output with per-request detector logs.
	nopLog := func(_, _, _ string) {}

	tracker := state.NewTracker(cfg, nopLog)
	sc := scorer.NewScorer(cfg.Scoring, buildDetectors(cfg), nopLog)

	// ── ThreatLogger: captures output into a slice ────────────────────────────────────
	// In production writeFn = utils.LogThreat (writes to file + console).
	// Here — captured in memory to verify format and content.
	var threatLines []string
	threatLogger := output.NewThreatLogger(func(ip string, score int, level string, modules []string, reason string) {
		line := output.FormatThreatLine(ip, score, level, modules, reason)
		threatLines = append(threatLines, line)
	})

	// ── Process example.access.log ───────────────────────────────────────────────────
	logPath := ".reference/example.access.log"
	f, err := os.Open(logPath)
	if err != nil {
		// File is not in git — a local artefact. Skip rather than fail
		// to distinguish missing test data from a logic error.
		t.Skipf("file %s unavailable, skipping e2e: %v", logPath, err)
	}
	defer f.Close()

	scan := bufio.NewScanner(f)
	for scan.Scan() {
		entry, ok := parser.Parse(scan.Text())
		if !ok {
			continue
		}
		ipState := tracker.Update(entry)
		level, score, modules, reason := sc.Evaluate(ipState, entry)
		threatLogger.Log(entry.RealIP, score, level, modules, reason)
	}
	if err := scan.Err(); err != nil {
		t.Fatalf("scan error reading %s: %v", logPath, err)
	}

	t.Logf("e2e: processed %s, threat/warn entries: %d", logPath, len(threatLines))

	// ── Assertion 1: at least one THREAT entry ────────────────────────────────────────
	// 185.177.72.23 (162 requests in 97 sec) → rate + UA(curl) → score > ban_threshold=80.
	threatCount := countLevel(threatLines, " THREAT ")
	if threatCount == 0 {
		t.Errorf("expected >= 1 THREAT entry, got 0 (total entries: %d)", len(threatLines))
		for _, line := range threatLines {
			t.Logf("  %s", line)
		}
	}

	// ── Assertion 2: all lines match the Fail2Ban regex ──────────────────────────────
	// Critical: if the format does not match, Fail2Ban will not block attackers.
	for _, line := range threatLines {
		if !fail2banRE.MatchString(line) {
			t.Errorf("line does not match Fail2Ban regex %q: %s", fail2banRE, line)
		}
	}

	// ── Assertion 3: 185.177.72.23 was caught as THREAT ──────────────────────────────
	// IP from documentation example: 162 requests in 97s with curl/8.7.1.
	const knownBadIP = "185.177.72.23"
	if !hasIPAtLevel(threatLines, knownBadIP, " THREAT ") {
		t.Errorf("expected THREAT for %s (rate+UA detectors), not found", knownBadIP)
		found := filterByIP(threatLines, knownBadIP)
		if len(found) == 0 {
			t.Logf("  %s did not appear in the threat log at all", knownBadIP)
		} else {
			for _, line := range found {
				t.Logf("  %s", line)
			}
		}
	}

	t.Logf("e2e: THREAT=%d, WARN=%d",
		threatCount,
		countLevel(threatLines, " WARN "),
	)
}

// ========================== Helper functions ===========================================

func countLevel(lines []string, level string) int {
	n := 0
	for _, line := range lines {
		if strings.Contains(line, level) {
			n++
		}
	}
	return n
}

func hasIPAtLevel(lines []string, ip, level string) bool {
	target := fmt.Sprintf("%s %s score=", level[1:len(level)-1], ip) // "THREAT 1.2.3.4 score="
	for _, line := range lines {
		if strings.Contains(line, target) {
			return true
		}
	}
	return false
}

func filterByIP(lines []string, ip string) []string {
	var result []string
	for _, line := range lines {
		if strings.Contains(line, " "+ip+" ") {
			result = append(result, line)
		}
	}
	return result
}
