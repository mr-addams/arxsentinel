package main

import (
	"os"
	"strings"
	"testing"
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
