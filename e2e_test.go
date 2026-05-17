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
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/mr-addams/nginx-sentinel/internal/core/output"
	"github.com/mr-addams/nginx-sentinel/internal/core/parser"
	"github.com/mr-addams/nginx-sentinel/internal/core/scorer"
	"github.com/mr-addams/nginx-sentinel/internal/core/state"
	"github.com/mr-addams/nginx-sentinel/internal/core/whitelist"
	"github.com/mr-addams/nginx-sentinel/internal/sys/config"
)

// e2eMaxLineBytes — scanner buffer limit matching tail.go:maxLineSize.
// Lines longer than this in the log file cause ErrTooLong → test fails via scan.Err().
const e2eMaxLineBytes = 64 * 1024

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
	scan.Buffer(make([]byte, e2eMaxLineBytes), e2eMaxLineBytes)
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

// TestE2ESynthetic runs the synthetic testdata/synthetic.access.log through the pipeline.
// Unlike TestE2E this file is committed to git — the test always runs in CI with -tags e2e.
//
// Attacker IP 10.0.0.1: sqlmap UA + probe paths → THREAT after 2nd request.
// Legitimate IP 10.0.0.2: normal browser UA + 200 responses → no threat log entries.
func TestE2ESynthetic(t *testing.T) {
	cfg, err := config.LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	nopLog := func(_, _, _ string) {}
	tracker := state.NewTracker(cfg, nopLog)
	sc := scorer.NewScorer(cfg.Scoring, buildDetectors(cfg), nopLog)

	var threatLines []string
	threatLogger := output.NewThreatLogger(func(ip string, score int, level string, modules []string, reason string) {
		line := output.FormatThreatLine(ip, score, level, modules, reason)
		threatLines = append(threatLines, line)
	})

	logPath := "testdata/synthetic.access.log"
	f, err := os.Open(logPath)
	if err != nil {
		t.Fatalf("cannot open %s: %v", logPath, err)
	}
	defer f.Close()

	scan := bufio.NewScanner(f)
	scan.Buffer(make([]byte, e2eMaxLineBytes), e2eMaxLineBytes)
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
		t.Fatalf("scan error: %v", err)
	}

	// ── Assertion 1: 10.0.0.1 must be caught as THREAT ───────────────────────────────
	const attackerIP = "10.0.0.1"
	if !hasIPAtLevel(threatLines, attackerIP, " THREAT ") {
		t.Errorf("expected THREAT for %s (sqlmap UA + probe paths), not found", attackerIP)
		for _, line := range filterByIP(threatLines, attackerIP) {
			t.Logf("  %s", line)
		}
	}

	// ── Assertion 2: 10.0.0.2 must not appear in threat log ──────────────────────────
	const legitimateIP = "10.0.0.2"
	if found := filterByIP(threatLines, legitimateIP); len(found) > 0 {
		t.Errorf("false positive: legitimate IP %s appeared in threat log", legitimateIP)
		for _, line := range found {
			t.Logf("  %s", line)
		}
	}

	// ── Assertion 3: all threat lines match Fail2Ban failregex ───────────────────────
	for _, line := range threatLines {
		if !fail2banRE.MatchString(line) {
			t.Errorf("line does not match Fail2Ban regex %q: %s", fail2banRE, line)
		}
	}

	t.Logf("synthetic e2e: THREAT=%d, WARN=%d",
		countLevel(threatLines, " THREAT "),
		countLevel(threatLines, " WARN "),
	)
}

// ========================== Task 11.1 — IPv6 attacker ================================
//
// Verifies that IPv6 addresses are parsed correctly and scored the same as IPv4.
// 2001:db8::1 uses sqlmap UA + probe paths → THREAT after the second request.
func TestE2EIPv6Attacker(t *testing.T) {
	cfg, err := config.LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	threatLines := runPipelineFromFile(t, "testdata/ipv6_attacker.access.log", cfg, nil)

	const attackerIPv6 = "2001:db8::1"
	if !hasIPAtLevel(threatLines, attackerIPv6, " THREAT ") {
		t.Errorf("expected THREAT for %s (sqlmap UA + probe paths), not found", attackerIPv6)
		for _, line := range filterByIP(threatLines, attackerIPv6) {
			t.Logf("  %s", line)
		}
		if len(filterByIP(threatLines, attackerIPv6)) == 0 {
			t.Logf("  %s did not appear in the threat log at all", attackerIPv6)
		}
	}

	t.Logf("ipv6 e2e: THREAT=%d, WARN=%d",
		countLevel(threatLines, " THREAT "),
		countLevel(threatLines, " WARN "),
	)
}

// ========================== Task 11.2 — Slow attack ===================================
//
// Verifies that low-volume automation traffic (1 request per 2 minutes) still
// accumulates enough score for detection. Rate detector does not fire — requests are
// spread over 1 hour. Bruteforce (67% 404 ratio) + automation UA trigger WARN or THREAT.
func TestE2ESlowAttack(t *testing.T) {
	cfg, err := config.LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	threatLines := runPipelineFromFile(t, "testdata/slow_attack.access.log", cfg, nil)

	total := countLevel(threatLines, " THREAT ") + countLevel(threatLines, " WARN ")
	if total == 0 {
		t.Errorf("expected at least one WARN or THREAT for slow automation scan, got 0")
		t.Logf("  processed slow_attack.access.log: no threats detected")
	}

	const attackerIP = "10.1.1.1"
	if !hasIPAtLevel(threatLines, attackerIP, " WARN ") && !hasIPAtLevel(threatLines, attackerIP, " THREAT ") {
		t.Errorf("expected WARN or THREAT for %s (automation scan + bruteforce), not found", attackerIP)
		t.Logf("  all threat entries: %v", threatLines)
	}

	t.Logf("slow attack e2e: %s — THREAT=%d, WARN=%d",
		attackerIP,
		countLevel(threatLines, " THREAT "),
		countLevel(threatLines, " WARN "),
	)
}

// ========================== Task 11.3 — False positive check =========================
//
// Verifies that normal high-volume browser traffic does not trigger THREAT.
// 4 IPs, 48 requests each, real browser UAs, <5% 404s — well below every detector threshold.
func TestE2EFalsePositive(t *testing.T) {
	cfg, err := config.LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	threatLines := runPipelineFromFile(t, "testdata/legit_highvolume.access.log", cfg, nil)

	threatCount := countLevel(threatLines, " THREAT ")
	if threatCount > 0 {
		t.Errorf("false positive: expected 0 THREAT entries for legitimate traffic, got %d", threatCount)
		for _, line := range threatLines {
			if strings.Contains(line, " THREAT ") {
				t.Logf("  %s", line)
			}
		}
	}

	// Count distinct IPs with WARN — allow at most 1 (edge cases in scoring are acceptable)
	warnIPs := make(map[string]struct{})
	for _, line := range threatLines {
		if strings.Contains(line, " WARN ") {
			if ip := extractIPFromThreatLine(line); ip != "" {
				warnIPs[ip] = struct{}{}
			}
		}
	}
	if len(warnIPs) > 1 {
		t.Errorf("false positive: expected ≤1 IP with WARN for legitimate traffic, got %d", len(warnIPs))
		for _, line := range threatLines {
			if strings.Contains(line, " WARN ") {
				t.Logf("  %s", line)
			}
		}
	}

	t.Logf("false positive e2e: THREAT=%d, WARN=%d (distinct IPs with WARN: %d)",
		threatCount,
		countLevel(threatLines, " WARN "),
		len(warnIPs),
	)
}

// ========================== Task 11.4 — Whitelisted IP ================================
//
// Verifies that an IP in whitelist.custom.ips is excluded from scoring even if it
// sends scanner traffic that would otherwise produce a THREAT.
func TestE2EWhitelistedCustomIP(t *testing.T) {
	cfg, err := config.LoadConfig("")
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	const whitelistedIP = "192.168.100.1"
	cfg.Whitelist.Custom.IPs = []string{whitelistedIP}

	matcher, err := whitelist.NewMatcher(cfg.Whitelist)
	if err != nil {
		t.Fatalf("whitelist.NewMatcher: %v", err)
	}

	// Inline log: whitelistedIP with sqlmap UA + probe paths — would score THREAT without whitelist.
	logLines := []string{
		whitelistedIP + ` - - [17/May/2026:13:00:01 +0000] "GET /wp-login.php HTTP/1.1" 404 162 "-" "sqlmap/1.7.11" "` + whitelistedIP + `"`,
		whitelistedIP + ` - - [17/May/2026:13:00:02 +0000] "GET /.env HTTP/1.1" 404 162 "-" "sqlmap/1.7.11" "` + whitelistedIP + `"`,
		whitelistedIP + ` - - [17/May/2026:13:00:03 +0000] "GET /.git/config HTTP/1.1" 404 162 "-" "sqlmap/1.7.11" "` + whitelistedIP + `"`,
		whitelistedIP + ` - - [17/May/2026:13:00:04 +0000] "GET /phpmyadmin/ HTTP/1.1" 404 162 "-" "sqlmap/1.7.11" "` + whitelistedIP + `"`,
		whitelistedIP + ` - - [17/May/2026:13:00:05 +0000] "GET /wp-admin/ HTTP/1.1" 404 162 "-" "sqlmap/1.7.11" "` + whitelistedIP + `"`,
	}

	tmpFile := t.TempDir() + "/whitelist_test.log"
	if err := os.WriteFile(tmpFile, []byte(strings.Join(logLines, "\n")+"\n"), 0o600); err != nil {
		t.Fatalf("cannot write temp log file: %v", err)
	}

	threatLines := runPipelineFromFile(t, tmpFile, cfg, matcher)

	if found := filterByIP(threatLines, whitelistedIP); len(found) > 0 {
		t.Errorf("whitelisted IP %s appeared in threat log (%d entries)", whitelistedIP, len(found))
		for _, line := range found {
			t.Logf("  %s", line)
		}
	}

	t.Logf("whitelist e2e: whitelisted IP %s not in threat log (total entries: %d)", whitelistedIP, len(threatLines))
}

// ========================== Helper functions ===========================================

// runPipelineFromFile processes a log file through the detection pipeline and returns
// all threat log lines. If matcher is non-nil, whitelisted IPs are skipped before
// tracking — matching the behaviour of processLine in production.
func runPipelineFromFile(t *testing.T, logPath string, cfg config.Config, matcher *whitelist.Matcher) []string {
	t.Helper()

	nopLog := func(_, _, _ string) {}
	tracker := state.NewTracker(cfg, nopLog)
	sc := scorer.NewScorer(cfg.Scoring, buildDetectors(cfg), nopLog)

	var threatLines []string
	threatLogger := output.NewThreatLogger(func(ip string, score int, level string, modules []string, reason string) {
		line := output.FormatThreatLine(ip, score, level, modules, reason)
		threatLines = append(threatLines, line)
	})

	f, err := os.Open(logPath)
	if err != nil {
		t.Fatalf("cannot open %s: %v", logPath, err)
	}
	defer f.Close()

	scan := bufio.NewScanner(f)
	scan.Buffer(make([]byte, e2eMaxLineBytes), e2eMaxLineBytes)
	for scan.Scan() {
		entry, ok := parser.Parse(scan.Text())
		if !ok {
			continue
		}
		if matcher != nil && matcher.IsWhitelistedIP(entry.RealIP) {
			continue
		}
		ipState := tracker.Update(entry)
		level, score, modules, reason := sc.Evaluate(ipState, entry)
		threatLogger.Log(entry.RealIP, score, level, modules, reason)
	}
	if err := scan.Err(); err != nil {
		t.Fatalf("scan error reading %s: %v", logPath, err)
	}

	return threatLines
}

// extractIPFromThreatLine parses the IP field from a FormatThreatLine output.
// Format: "TIMESTAMP LEVEL IP score=N ..." — IP is the third whitespace-separated field.
func extractIPFromThreatLine(line string) string {
	parts := strings.Fields(line)
	if len(parts) < 3 {
		return ""
	}
	return parts[2]
}

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
	levelClean := strings.TrimSpace(level)
	for _, line := range lines {
		// Check IP and level independently — does not depend on field order in FormatThreatLine.
		if strings.Contains(line, " "+ip+" ") && strings.Contains(line, " "+levelClean+" ") {
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
