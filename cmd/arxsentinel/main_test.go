package main

import (
	"context"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mr-addams/arxsentinel/internal/core/parser"
	"github.com/mr-addams/arxsentinel/internal/core/scorer"
	"github.com/mr-addams/arxsentinel/internal/core/state"
	"github.com/mr-addams/arxsentinel/internal/core/whitelist"
	"github.com/mr-addams/arxsentinel/internal/sys/config"
	"github.com/mr-addams/arxsentinel/internal/sys/utils"
	"github.com/mr-addams/arxsentinel/pkg/plugin"
)

// TestStartupShutdownInvariants enforces the mandatory startup/shutdown specification
// documented in .claude/CLAUDE.md. This test acts as a static guard — it must pass
// before every commit touching main.go or any goroutine lifecycle code.
//
// If this test fails, do NOT bypass it. Fix the violation instead.
func TestStartupShutdownInvariants(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("cannot read main.go: %v", err)
	}
	text := string(src)

	check := func(name, needle string) {
		t.Helper()
		if !strings.Contains(text, needle) {
			t.Errorf("INVARIANT VIOLATED — %s\n  expected to find: %q", name, needle)
		}
	}
	checkCount := func(name, needle string, want int) {
		t.Helper()
		got := strings.Count(text, needle)
		if got != want {
			t.Errorf("INVARIANT VIOLATED — %s\n  expected %d occurrences of %q, got %d",
				name, want, needle, got)
		}
	}
	forbid := func(name, needle, hint string) {
		t.Helper()
		if strings.Contains(text, needle) {
			t.Errorf("INVARIANT VIOLATED — %s\n  forbidden pattern found: %q\n  hint: %s",
				name, needle, hint)
		}
	}

	// ── Specification comments must be present ────────────────────────────────────────
	// Guards against documentation drift: if the sequence changes, the comment must too.

	check("startup sequence spec present",
		"STARTUP SEQUENCE")
	check("shutdown sequence spec present",
		"SHUTDOWN SEQUENCE")

	// ── Root context ──────────────────────────────────────────────────────────────────
	// The application root context must be created from signal.NotifyContext so that
	// SIGTERM/SIGINT automatically cancels all goroutines.

	check("root ctx created via signal.NotifyContext",
		"signal.NotifyContext(context.Background()")

	// ── Goroutine contexts must derive from appCtx ────────────────────────────────────
	// context.WithCancel(context.Background()) creates a goroutine that ignores SIGTERM.
	// Goroutines must use appCtx or a context derived from it.
	//
	// Allowed exception: context.WithTimeout(context.Background(), ...) for the metrics
	// server shutdown — that goroutine needs a FRESH context because appCtx is already
	// cancelled at that point. It is a one-shot operation context, not a goroutine root.

	forbid("no goroutine root ctx from Background()",
		"context.WithCancel(context.Background())",
		"use appCtx (or a derived context) instead of context.Background()")

	// ── Resource-holding goroutines must be tracked ───────────────────────────────────
	// Every goroutine that holds resources (file handles, network connections, etc.)
	// must be tracked in a WaitGroup so main() does not exit before cleanup finishes.
	//
	// metricsWg must track BOTH metrics goroutines:
	//   1. ListenAndServe — holds the TCP listener (network resource)
	//   2. shutdown goroutine — calls srv.Shutdown(), must complete before main() exits
	//
	// A single metricsWg.Add(1) would mean one goroutine is untracked — which is the
	// exact bug this check exists to prevent. Two Add calls = two goroutines tracked.

	checkCount("both metrics goroutines tracked in metricsWg",
		"metricsWg.Add(1)", 2)

	check("metricsWg waited in main",
		"metricsWg.Wait()")

	check("stream goroutines tracked in wg",
		"wg.Wait()")
}

// TestProcessLine_ChainGuardNilSafe verifies that processLine does not panic when
// SharedResources.ChainChecker and WarningsWriter are nil (chain_guard disabled).
// This is the normal state for configs that do not set chain_guard.enabled = true.
func TestProcessLine_ChainGuardNilSafe(t *testing.T) {
	// Initialise utils logger (no-op output) so processLine can call utils.Log safely.
	if err := utils.Init(false, false, "", ""); err != nil {
		t.Fatalf("utils.Init: %v", err)
	}
	defer utils.Close()

	// Load from an empty YAML — LoadConfig fills all fields from internal defaults.
	// Using a temp file avoids a dependency on unexported defaultConfig().
	tmp, err := os.CreateTemp(t.TempDir(), "cfg-*.yaml")
	if err != nil {
		t.Fatalf("create temp config: %v", err)
	}
	// Minimal valid config: one stream, no chain_guard section.
	_, _ = tmp.WriteString(`
general:
  log_file: /dev/null
  threat_log: /dev/null
`)
	_ = tmp.Close()

	cfg, loadErr := config.LoadConfig(tmp.Name())
	if loadErr != nil {
		t.Fatalf("config.LoadConfig: %v", loadErr)
	}

	tracker := state.NewTracker(cfg, func(tag, msg, level string) {})
	matcher, err := whitelist.NewMatcher(cfg.Whitelist)
	if err != nil {
		t.Fatalf("whitelist.NewMatcher: %v", err)
	}

	var count atomic.Int64
	var threatCount atomic.Int64

	pipe := &PipelineContext{
		StreamName:       "test",
		processedCount:   &count,
		threatCount:      &threatCount,
		Tracker:          tracker,
		Scorer:           scorer.NewScorer(cfg.Scoring, nil, func(tag, msg, level string) {}),
		Sinks:            []plugin.Sink{}, // no-op sink list — we do not assert on threat output here
		Matcher:          matcher,
		Verifier:         whitelist.NewVerifier(whitelist.NewIPCache(cfg.Whitelist.DNSCache), nil, func(tag, msg, level string) {}),
		FakeBotScore:     cfg.Whitelist.FakeBotScore,
		DNSVerifyTimeout: time.Duration(cfg.Whitelist.DNSVerifyTimeout),
		// Shared is zero-value: ChainChecker == nil, WarningsWriter == nil.
		// This simulates chain_guard.enabled = false (the default).
		Shared:     SharedResources{},
		SourceName: "file:/var/log/nginx/access.log",
		SourceType: "file",
	}

	// A valid nginx combined + real_ip log line (the format CombinedParser expects).
	// Format: $remote_addr ... "$http_user_agent" "$real_ip"
	rawLine := `203.0.113.1 - - [20/May/2026:10:00:00 +0000] "GET /wp-login.php HTTP/1.1" 200 512 "-" "curl/7.88" "203.0.113.1"`
	entry, ok := (&parser.CombinedParser{}).Parse(rawLine)
	if !ok {
		t.Fatal("test setup: CombinedParser failed to parse the test line")
	}

	// Must not panic.
	processLine(context.Background(), entry, pipe)

	if count.Load() == 0 {
		t.Error("processLine returned without incrementing processedCount for a valid log entry")
	}
}
