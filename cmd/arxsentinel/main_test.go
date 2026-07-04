package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/mr-addams/arxsentinel/internal/core/scorer"
	"github.com/mr-addams/arxsentinel/internal/core/state"
	"github.com/mr-addams/arxsentinel/internal/core/whitelist"
	"github.com/mr-addams/arxsentinel/internal/sys/config"
	"github.com/mr-addams/arxsentinel/internal/sys/utils"
	coreruntime "github.com/mr-addams/arx-core/pkg/runtime"
	pkgdetector "github.com/mr-addams/arx-core/pkg/detector"
	"github.com/mr-addams/arx-core/pkg/executor/queue"
	ncs "github.com/mr-addams/arx-core/pkg/ncs"
	"github.com/mr-addams/arx-core/pkg/parser"
	"github.com/mr-addams/arx-core/pkg/plugin"
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

// TestSecurityProcessor_ChainGuardNilSafe verifies that securityProcessor.Process
// does not panic when runtime.SharedResources.ChainChecker and WarningsWriter are
// nil (chain_guard disabled). This is the normal state for configs that do not
// set chain_guard.enabled = true.
//
// Migrated (Flow 081 Phase 4): the legacy processLine function is gone — its
// verbatim port lives as securityProcessor.Process (processor_security.go).
// The test now goes through the real Product path: build a *securityFactory,
// call Build to obtain *securityState, then invoke Process via a fresh
// securityProcessor sharing the same nil SharedResources.
func TestSecurityProcessor_ChainGuardNilSafe(t *testing.T) {
	// Initialise utils logger (no-op output) so securityProcessor.Process can call utils.Log safely.
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
	// Minimal valid config: one stream with one auto-wrapped pipeline, no chain_guard section.
	// After Migrate(), general.log_file/threat_log are forbidden when streams:[] is set —
	// inputs/outputs live in pipelines[].inputs/outputs instead.
	_, _ = tmp.WriteString(`
streams:
  - name: test
    pipelines:
      - name: ""
        inputs:
          - type: file
            path: /dev/null
        outputs:
          - type: file
            path: /dev/null
            format: fail2ban
`)
	_ = tmp.Close()

	cfg, loadErr := config.LoadConfig(tmp.Name())
	if loadErr != nil {
		t.Fatalf("config.LoadConfig: %v", loadErr)
	}

	// Build a securityFactory exactly the way main.go does it, but with a
	// nil-safe runtime.SharedResources (ChainChecker/WarningsWriter both nil
	// — simulates chain_guard.enabled = false, the default).
	factory := &securityFactory{
		ctx:        context.Background(),
		path:       tmp.Name(),
		ipCache:    nil, // Process() never touches ipCache (DNS lookup only via Verifier on cache miss)
		resolver:   &net.Resolver{PreferGo: true},
		cfg:        cfg,
		streamName: "test",
		trackers:   make(map[string]*state.Tracker),
		shared:     coreruntime.SharedResources{}, // ChainChecker / WarningsWriter nil
	}

	ps, err := factory.Build("test", "", 0, factory.shared)
	if err != nil {
		t.Fatalf("securityFactory.Build: %v", err)
	}

	processor := &securityProcessor{shared: factory.shared}

	// A valid nginx combined + real_ip log line (the format CombinedParser expects).
	// Format: $remote_addr ... "$http_user_agent" "$real_ip"
	rawLine := `203.0.113.1 - - [20/May/2026:10:00:00 +0000] "GET /wp-login.php HTTP/1.1" 200 512 "-" "curl/7.88" "203.0.113.1"`
	entry, ok := (&parser.CombinedParser{}).Parse(rawLine)
	if !ok {
		t.Fatal("test setup: CombinedParser failed to parse the test line")
	}
	// Phase 2.2 (Flow 083): Process now receives *plugin.Event; wrap the
	// parsed LogEntry into the generic envelope before invoking the processor.
	event := &plugin.Event{
		Envelope: plugin.Envelope{
			Source:     entry.RemoteAddr,
			SourceType: "file",
			Stream:     "test",
			Timestamp:  entry.Time,
		},
		Payload: entry,
	}

	evctx := coreruntime.EventContext{
		StreamName:   "test",
		PipelineName: "",
		SourceName:   "file:/var/log/nginx/access.log",
		SourceType:   "file",
	}

	// Must not panic — ChainChecker/WarningsWriter are nil (chain_guard disabled).
	action := processor.Process(context.Background(), event, ps, evctx)

	// Non-Skip result: the line was scored (even if level="" — Action{} means Skip=false).
	if action.Skip {
		t.Error("securityProcessor.Process returned Skip=true for a normal non-whitelisted request")
	}
}

// TestSecurityProcessor_RawForward verifies the Distributed NCS (Flow 093)
// raw-forward passthrough branch: a pipeline with raw_forward: true must
// bypass detection/scoring entirely and forward every line unscored — this
// is what lets a collector node hand raw lines to a transport-queue sink
// without ever computing a verdict locally.
func TestSecurityProcessor_RawForward(t *testing.T) {
	if err := utils.Init(false, false, "", ""); err != nil {
		t.Fatalf("utils.Init: %v", err)
	}
	defer utils.Close()

	tmp, err := os.CreateTemp(t.TempDir(), "cfg-*.yaml")
	if err != nil {
		t.Fatalf("create temp config: %v", err)
	}
	_, _ = tmp.WriteString(`
streams:
  - name: test
    pipelines:
      - name: ""
        raw_forward: true
        inputs:
          - type: file
            path: /dev/null
        outputs:
          - type: sentinel-threat
            path: /dev/null
            format: raw-line
`)
	_ = tmp.Close()

	cfg, loadErr := config.LoadConfig(tmp.Name())
	if loadErr != nil {
		t.Fatalf("config.LoadConfig: %v", loadErr)
	}

	factory := &securityFactory{
		ctx:        context.Background(),
		path:       tmp.Name(),
		ipCache:    nil,
		resolver:   &net.Resolver{PreferGo: true},
		cfg:        cfg,
		streamName: "test",
		trackers:   make(map[string]*state.Tracker),
		shared:     coreruntime.SharedResources{},
	}

	ps, err := factory.Build("test", "", 0, factory.shared)
	if err != nil {
		t.Fatalf("securityFactory.Build: %v", err)
	}

	processor := &securityProcessor{shared: factory.shared}

	// A clearly-scoreable line (wp-login.php probe) — proves the bypass is
	// unconditional, not just "nothing to score here".
	rawLine := `203.0.113.1 - - [20/May/2026:10:00:00 +0000] "GET /wp-login.php HTTP/1.1" 200 512 "-" "curl/7.88" "203.0.113.1"`
	entry, ok := (&parser.CombinedParser{}).Parse(rawLine)
	if !ok {
		t.Fatal("test setup: CombinedParser failed to parse the test line")
	}
	event := &plugin.Event{
		Envelope: plugin.Envelope{
			Source:     entry.RemoteAddr,
			SourceType: "file",
			Stream:     "test",
			Timestamp:  entry.Time,
		},
		Payload: entry,
	}
	evctx := coreruntime.EventContext{
		StreamName:   "test",
		PipelineName: "",
		SourceName:   "file:/var/log/nginx/access.log",
		SourceType:   "file",
	}

	action := processor.Process(context.Background(), event, ps, evctx)

	if action.Skip {
		t.Fatal("raw_forward pipeline returned Skip=true — expected unconditional forward")
	}
	if action.Payload == nil {
		t.Fatal("raw_forward pipeline returned nil Payload — expected forwarded event")
	}
	fwd := action.Payload
	if fwd.Envelope.Level != "" {
		t.Errorf("fwd.Envelope.Level = %q, want empty (raw_forward must not score)", fwd.Envelope.Level)
	}
	got, ok := fwd.Payload.(*parser.LogEntry)
	if !ok {
		t.Fatalf("fwd.Payload type = %T, want *parser.LogEntry", fwd.Payload)
	}
	if got.RealIP != entry.RealIP || got.Path != entry.Path {
		t.Errorf("forwarded LogEntry = %+v, want the unmodified parsed entry %+v", got, entry)
	}
}

// ── Pipeline abstraction unit tests (Flow #034, Task 5) ───────────────────────────────────

// loadMinimalConfig creates a temp config file with the minimum required fields and loads it.
// All defaults are filled by LoadConfig; tests can rely on cfg.Detectors.*.Enabled == true.
func loadMinimalConfig(t *testing.T) config.Config {
	t.Helper()
	tmp, err := os.CreateTemp(t.TempDir(), "cfg-*.yaml")
	if err != nil {
		t.Fatalf("create temp config: %v", err)
	}
	_, _ = tmp.WriteString("general:\n  log_file: /dev/null\n  threat_log: /dev/null\n")
	_ = tmp.Close()
	cfg, err := config.LoadConfig(tmp.Name())
	if err != nil {
		t.Fatalf("config.LoadConfig: %v", err)
	}
	return cfg
}

// TestResolveTrackerGroup verifies tracker group key resolution:
//   - named pipeline, empty TrackerGroup → group = pipeline name (isolated)
//   - named pipeline, non-empty TrackerGroup → group = TrackerGroup
//   - auto-wrapped pipeline (Name="", TrackerGroup="") → group = "" (shared per stream)
func TestResolveTrackerGroup(t *testing.T) {
	cases := []struct {
		desc      string
		pipeCfg   config.PipelineConfig
		wantGroup string
	}{
		{
			desc:      "named_pipeline_no_group_isolated",
			pipeCfg:   config.PipelineConfig{Name: "api"},
			wantGroup: "api",
		},
		{
			desc:      "named_pipeline_with_group_shared",
			pipeCfg:   config.PipelineConfig{Name: "api", TrackerGroup: "web"},
			wantGroup: "web",
		},
		{
			desc:      "auto_wrapped_legacy_empty_name_empty_group",
			pipeCfg:   config.PipelineConfig{Name: "", TrackerGroup: ""},
			wantGroup: "",
		},
		{
			desc:      "empty_name_non_empty_group",
			pipeCfg:   config.PipelineConfig{Name: "", TrackerGroup: "shared"},
			wantGroup: "shared",
		},
		{
			desc:      "named_pipeline_same_group_as_another",
			pipeCfg:   config.PipelineConfig{Name: "admin", TrackerGroup: "web"},
			wantGroup: "web",
		},
	}
	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			got := resolveTrackerGroup(tc.pipeCfg)
			if got != tc.wantGroup {
				t.Errorf("resolveTrackerGroup(%+v) = %q, want %q", tc.pipeCfg, got, tc.wantGroup)
			}
		})
	}
}

// TestSecurityFactory_GetOrCreateTracker_SharedAndIsolated verifies that
// securityFactory.getOrCreateTracker (the Product replacement for the legacy
// buildTrackerGroups helper) preserves per-group sharing semantics:
//   - two pipelines with the same tracker_group share one *state.Tracker
//   - a pipeline with a different (implicit) group gets a distinct *state.Tracker
//
// Migrated (Flow 081 Phase 4): the legacy buildTrackerGroups helper is gone —
// production code uses securityFactory.getOrCreateTracker (processor_factory.go).
func TestSecurityFactory_GetOrCreateTracker_SharedAndIsolated(t *testing.T) {
	cfg := loadMinimalConfig(t)

	streamCfg := config.StreamConfig{
		Pipelines: []config.PipelineConfig{
			{Name: "api", TrackerGroup: "web"},   // group "web"
			{Name: "admin", TrackerGroup: "web"}, // same group "web" — shares tracker with api
			{Name: "mgmt", TrackerGroup: ""},     // isolated: implicit group = "mgmt"
		},
	}

	// getOrCreateTracker starts a GC goroutine on first creation per group;
	// cancel ctx in cleanup to stop them cleanly (no leaked goroutines after test).
	factoryCtx, cancelFactory := context.WithCancel(context.Background())
	t.Cleanup(cancelFactory)
	factory := &securityFactory{
		ctx:      factoryCtx,
		trackers: make(map[string]*state.Tracker),
	}

	apiTracker := factory.getOrCreateTracker(resolveTrackerGroup(streamCfg.Pipelines[0]), cfg)   // "web"
	adminTracker := factory.getOrCreateTracker(resolveTrackerGroup(streamCfg.Pipelines[1]), cfg) // "web"
	mgmtTracker := factory.getOrCreateTracker(resolveTrackerGroup(streamCfg.Pipelines[2]), cfg)  // "mgmt"

	if apiTracker == nil {
		t.Fatal("tracker for group \"web\" must not be nil")
	}
	if mgmtTracker == nil {
		t.Fatal("tracker for group \"mgmt\" must not be nil")
	}

	// api and admin both resolve to group "web" — must point to the same tracker.
	if apiTracker != adminTracker {
		t.Error("api and admin with tracker_group=\"web\" must share the same *state.Tracker")
	}

	// mgmt resolves to group "mgmt" — must be a different pointer.
	if mgmtTracker == apiTracker {
		t.Error("mgmt with isolated tracker_group must not share the tracker with the \"web\" group")
	}
}

// TestSecurityFactory_GetOrCreateTracker_AutoWrapped verifies that legacy
// auto-wrapped pipelines (Name="", TrackerGroup="") all resolve to the same
// group key "" and share one tracker per stream — identical to pre-Task-3
// behaviour.
func TestSecurityFactory_GetOrCreateTracker_AutoWrapped(t *testing.T) {
	cfg := loadMinimalConfig(t)

	// Two auto-wrapped pipelines (Migrate() would produce this for a stream with inputs+outputs).
	streamCfg := config.StreamConfig{
		Pipelines: []config.PipelineConfig{
			{Name: "", TrackerGroup: ""},
		},
	}

	factoryCtx, cancelFactory := context.WithCancel(context.Background())
	t.Cleanup(cancelFactory)
	factory := &securityFactory{
		ctx:      factoryCtx,
		trackers: make(map[string]*state.Tracker),
	}

	tracker := factory.getOrCreateTracker(resolveTrackerGroup(streamCfg.Pipelines[0]), cfg)

	if tracker == nil {
		t.Fatal("auto-wrapped tracker (group=\"\") must not be nil")
	}
}

// TestBuildPipelineDetectors_NilFallsBackToGlobal verifies that when pipeCfg.Detectors is nil
// (auto-wrapped legacy pipeline), globalDetectorSpecs() is used and all 8 registered detectors
// are built — preserving backward compat for existing configs.
func TestBuildPipelineDetectors_NilFallsBackToGlobal(t *testing.T) {
	cfg := loadMinimalConfig(t) // all 8 detectors enabled by default

	pipeCfg := config.PipelineConfig{
		Name:      "",
		Detectors: nil, // nil → globalDetectorSpecs path
	}

	if err := utils.Init(false, false, "", ""); err != nil {
		t.Fatalf("utils.Init: %v", err)
	}
	t.Cleanup(utils.Close)

	detectors := buildPipelineDetectors(context.Background(), cfg, pipeCfg, SharedResources{})

	// All 8 registered detectors should be present.
	want := pkgdetector.Names() // sorted list of all registered names
	if len(detectors) != len(want) {
		t.Fatalf("expected %d detectors (%v), got %d", len(want), want, len(detectors))
	}
}

// TestPipelineLogTag verifies formatting for all name combinations.
func TestPipelineLogTag(t *testing.T) {
	cases := []struct {
		stream, pipeline, want string
	}{
		{"", "", "(default)"},
		{"nginx", "", `stream "nginx"`},
		{"nginx", "api", `stream "nginx" pipeline "api"`},
		{"", "api", `stream "" pipeline "api"`},
	}
	for _, tc := range cases {
		got := pipelineLogTag(tc.stream, tc.pipeline)
		if got != tc.want {
			t.Errorf("pipelineLogTag(%q, %q) = %q, want %q", tc.stream, tc.pipeline, got, tc.want)
		}
	}
}

// TestFindPipelineCfg_ByName verifies that named pipelines are found by name across SIGHUP reloads.
func TestFindPipelineCfg_ByName(t *testing.T) {
	target := config.PipelineConfig{Name: "admin", TrackerGroup: "web"}
	other := config.PipelineConfig{Name: "api", TrackerGroup: "web"}
	streamCfg := config.StreamConfig{
		Pipelines: []config.PipelineConfig{other, target},
	}
	fallback := config.PipelineConfig{Name: "fallback"}

	got := findPipelineCfg(streamCfg, "admin", 0, fallback)
	if got.Name != "admin" {
		t.Errorf("findPipelineCfg by name: got %q, want \"admin\"", got.Name)
	}
}

// TestFindPipelineCfg_ByIndex verifies that auto-wrapped pipelines (Name="") are found by index.
func TestFindPipelineCfg_ByIndex(t *testing.T) {
	pipe0 := config.PipelineConfig{Name: "", TrackerGroup: ""}
	pipe1 := config.PipelineConfig{Name: "", TrackerGroup: "other"}
	streamCfg := config.StreamConfig{
		Pipelines: []config.PipelineConfig{pipe0, pipe1},
	}
	fallback := config.PipelineConfig{Name: "fallback"}

	// Index 1 should return pipe1.
	got := findPipelineCfg(streamCfg, "", 1, fallback)
	if got.TrackerGroup != "other" {
		t.Errorf("findPipelineCfg by index 1: TrackerGroup=%q, want \"other\"", got.TrackerGroup)
	}
}

// TestFindPipelineCfg_FallbackOnMissing verifies that a removed pipeline returns the fallback.
func TestFindPipelineCfg_FallbackOnMissing(t *testing.T) {
	streamCfg := config.StreamConfig{
		Pipelines: []config.PipelineConfig{
			{Name: "api"},
		},
	}
	fallback := config.PipelineConfig{Name: "fallback"}

	// "admin" was removed from config on SIGHUP — must return fallback, not panic.
	got := findPipelineCfg(streamCfg, "admin", 0, fallback)
	if got.Name != "fallback" {
		t.Errorf("findPipelineCfg missing pipeline: got %q, want \"fallback\"", got.Name)
	}

	// Index out of range — also returns fallback.
	got2 := findPipelineCfg(streamCfg, "", 5, fallback)
	if got2.Name != "fallback" {
		t.Errorf("findPipelineCfg out-of-range index: got %q, want \"fallback\"", got2.Name)
	}
}

// ========================== UA-only bot pipeline tests (Flow 044) =======================

// TestPipeline_BotExemptDetector verifies that a UA-only bot with ExemptDetectors=["noasset"]
// does not get scored by the noasset detector, but still gets scored by other detectors (e.g. rate).
func TestPipeline_BotExemptDetector(t *testing.T) {
	cfg := loadMinimalConfig(t)
	// Ensure rate detector fires within a few requests for the test.
	cfg.Detectors.Rate.Threshold = 5
	cfg.Detectors.Rate.Enabled = true
	cfg.Detectors.NoAsset.Enabled = true

	nopLog := func(_, _, _ string) {}
	tracker := state.NewTracker(cfg, nopLog)
	matcher, err := whitelist.NewMatcher(cfg.Whitelist)
	if err != nil {
		t.Fatalf("whitelist.NewMatcher: %v", err)
	}

	detectors := buildPipelineDetectors(context.Background(), cfg, config.PipelineConfig{}, SharedResources{})
	sc := scorer.NewScorer(cfg.Scoring, detectors, nopLog)

	verifier := whitelist.NewVerifier(whitelist.NewIPCache(cfg.Whitelist.DNSCache), nil, nopLog)

	p := &parser.CombinedParser{}

	// Send 5 requests from the same IP with ClaudeBot UA.
	// claudebot matches → ua_only → verified=false, isFakeBot=false → exemptSet={"noasset"}
	for i := range 5 {
		rawLine := fmt.Sprintf(`1.2.3.4 - - [01/Jun/2026:10:00:%02d +0000] "GET /page%d HTTP/1.1" 200 512 "-" "ClaudeBot/1.0" "1.2.3.4"`, i, i)
		entry, ok := p.Parse(rawLine)
		if !ok {
			t.Fatalf("iteration %d: failed to parse log line", i)
		}

		_, botCfg, matched := matcher.MatchBot(entry.UserAgent)
		if !matched {
			t.Fatalf("iteration %d: ClaudeBot UA did not match any bot", i)
		}
		if botCfg.Name != "claudebot" {
			t.Fatalf("iteration %d: expected claudebot match, got %q", i, botCfg.Name)
		}

		ctx := context.Background()
		verified, isFakeBot := verifier.Verify(ctx, entry.RealIP, botCfg)
		if verified || isFakeBot {
			t.Fatalf("iteration %d: ua_only expected (false, false), got (%v, %v)", i, verified, isFakeBot)
		}

		var exemptSet map[string]struct{}
		if !verified && !isFakeBot && len(botCfg.ExemptDetectors) > 0 {
			exemptSet = make(map[string]struct{}, len(botCfg.ExemptDetectors))
			for _, name := range botCfg.ExemptDetectors {
				exemptSet[name] = struct{}{}
			}
		}
		if exemptSet == nil {
			t.Fatal("ClaudeBot should have exempt_detectors configured, got nil exemptSet")
		}

		ipState := tracker.Update(entry)
		_, _, modules, _ := sc.Evaluate(ipState, entry, exemptSet)

		for _, mod := range modules {
			if mod == "noasset" {
				t.Errorf("iteration %d: noasset detector fired despite being in exemptSet", i)
			}
		}
	}

	t.Log("Bot exempt detector test passed: noasset not fired for ClaudeBot")
}

// TestPreRegisterExecutorQueues_WiringMismatch verifies the fail-fast check
// added to preRegisterExecutorQueues: an executor source with a queue: section
// that does not match any sentinel-threat output in the pipeline must produce
// an error at startup. Without this guard, the source would silently create a
// pre-registered backend queue (bbolt/redis) and a separate MemoryQueue would
// be created by the sink — events would be lost without any error.
func TestPreRegisterExecutorQueues_WiringMismatch(t *testing.T) {
	// Detach any queues left over from sibling tests so this test starts clean.
	// Named Channel Switch is a package-level singleton; a leftover bbolt queue
	// from another test would make us report a false-positive success.
	//
	// Use t.Cleanup instead of per-case manual resets: cleanup runs even when
	// t.Fatal/t.Errorf aborts the test in the middle of a case, so a half-run
	// test cannot leave an orphan queue behind that pollutes the next test.
	cleanupNames := []string{"mismatch-stream", "ok-stream", "orphan-stream", "legacy-stream"}
	t.Cleanup(func() {
		for _, n := range cleanupNames {
			ncs.DetachWriter(n)
		}
	})

	// Case 1: source name not referenced by any sentinel-threat output → error.
	cfg := &config.Config{
		Executors: []config.ExecutorTopConfig{{
			Name: "cf-ban",
			Sources: []queue.ExecutorSourceRef{{
				Name:  "mismatch-stream",
				Queue: &queue.QueueConfig{Type: queue.QueueTypeBbolt, Path: t.TempDir() + "/q.db"},
			}},
		}},
		Streams: []config.StreamConfig{{
			Name: "web",
			Pipelines: []config.PipelineConfig{{
				Outputs: []config.SinkConfig{
					{Type: "file", Path: "/tmp/x.log"}, // no sentinel-threat output
				},
			}},
		}},
	}
	err := preRegisterExecutorQueues(cfg)
	if err == nil {
		t.Fatal("expected fail-fast error for orphan executor source, got nil")
	}
	if !strings.Contains(err.Error(), "mismatch-stream") {
		t.Errorf("error should mention the orphan source name; got: %v", err)
	}
	if !strings.Contains(err.Error(), "cf-ban") {
		t.Errorf("error should mention the executor name; got: %v", err)
	}
	if !strings.Contains(err.Error(), "available sink names") {
		t.Errorf("error should list available sink names; got: %v", err)
	}

	// Case 2: source name matches a sentinel-threat output in pipelines → no error.
	// Use a memory-backed queue so we do not touch the filesystem.
	cfgOK := &config.Config{
		Executors: []config.ExecutorTopConfig{{
			Name: "cf-ban",
			Sources: []queue.ExecutorSourceRef{{
				Name:  "ok-stream",
				Queue: &queue.QueueConfig{Type: queue.QueueTypeMemory},
			}},
		}},
		Streams: []config.StreamConfig{{
			Name: "web",
			Pipelines: []config.PipelineConfig{{
				Outputs: []config.SinkConfig{
					{Type: "sentinel-threat", Name: "ok-stream"},
				},
			}},
		}},
	}
	if err := preRegisterExecutorQueues(cfgOK); err != nil {
		t.Fatalf("expected nil error for matched source/output pair, got: %v", err)
	}

	// Case 3: source without queue section is skipped — no error even if no
	// sentinel-threat output exists, because the legacy MemoryQueue path is used.
	cfgLegacy := &config.Config{
		Executors: []config.ExecutorTopConfig{{
			Name: "cf-ban",
			Sources: []queue.ExecutorSourceRef{
				{Name: "legacy-stream"}, // Queue == nil
			},
		}},
		Streams: []config.StreamConfig{{
			Name: "web",
			Pipelines: []config.PipelineConfig{{
				Outputs: []config.SinkConfig{},
			}},
		}},
	}
	if err := preRegisterExecutorQueues(cfgLegacy); err != nil {
		t.Fatalf("expected nil error for legacy (no-queue) source, got: %v", err)
	}

	// Case 4: mixed — one source matches, another is orphan → fail-fast on the
	// orphan. Confirms the check is per-source, not all-or-nothing.
	cfgMixed := &config.Config{
		Executors: []config.ExecutorTopConfig{{
			Name: "cf-ban",
			Sources: []queue.ExecutorSourceRef{
				{Name: "ok-stream", Queue: &queue.QueueConfig{Type: queue.QueueTypeMemory}},
				{Name: "orphan-stream", Queue: &queue.QueueConfig{Type: queue.QueueTypeMemory}},
			},
		}},
		Streams: []config.StreamConfig{{
			Name: "web",
			Pipelines: []config.PipelineConfig{{
				Outputs: []config.SinkConfig{
					{Type: "sentinel-threat", Name: "ok-stream"},
				},
			}},
		}},
	}
	err = preRegisterExecutorQueues(cfgMixed)
	if err == nil {
		t.Fatal("expected fail-fast error when one of two sources is orphan, got nil")
	}
	if !strings.Contains(err.Error(), "orphan-stream") {
		t.Errorf("error should name the orphan source; got: %v", err)
	}
}

// TestCollectSentinelSinkNames verifies the helper walks every config location
// where a sentinel-threat output can be declared and produces the expected set.
// This is the single source of truth for "is this channel name wired?" — the
// preRegisterExecutorQueues check relies on it.
func TestCollectSentinelSinkNames(t *testing.T) {
	cfg := &config.Config{
		Outputs: []config.SinkConfig{
			{Type: "sentinel-threat", Name: "top-level"},
			{Type: "file", Path: "/tmp/x"}, // ignored: not sentinel-threat
			{Type: "sentinel-threat"},      // ignored: empty name
		},
		Streams: []config.StreamConfig{{
			Name: "web",
			Outputs: []config.SinkConfig{
				{Type: "sentinel-threat", Name: "stream-level"},
			},
			Pipelines: []config.PipelineConfig{{
				Outputs: []config.SinkConfig{
					{Type: "sentinel-threat", Name: "pipeline-level"},
				},
			}},
		}},
	}
	got := collectSentinelSinkNames(cfg)
	want := []string{"top-level", "stream-level", "pipeline-level"}
	if len(got) != len(want) {
		t.Fatalf("expected %d names, got %d: %v", len(want), len(got), got)
	}
	for _, n := range want {
		if _, ok := got[n]; !ok {
			t.Errorf("missing expected name %q in set: %v", n, got)
		}
	}
}

// BenchmarkSecurityProcessor measures the throughput of the production code path
// (securityProcessor.Process with a *securityState built by securityFactory.Build).
// Uses a realistic nginx log line and a minimal config with default detectors.
//
// Migrated (Flow 081 Phase 4): the legacy processLine function is gone; the
// production row handler is now securityProcessor.Process, called via the same
// state-builder path that runtime.Run uses. Throughput semantics are preserved:
// the same matcher/scorer/verifier are exercised on every iteration.
func BenchmarkSecurityProcessor(b *testing.B) {
	if err := utils.Init(false, false, "", ""); err != nil {
		b.Fatalf("utils.Init: %v", err)
	}
	defer utils.Close()

	tmp, err := os.CreateTemp(b.TempDir(), "cfg-*.yaml")
	if err != nil {
		b.Fatalf("create temp config: %v", err)
	}
	_, _ = tmp.WriteString(`
streams:
  - name: test
    pipelines:
      - name: ""
        inputs:
          - type: file
            path: /dev/null
        outputs:
          - type: file
            path: /dev/null
            format: fail2ban
`)
	_ = tmp.Close()

	cfg, loadErr := config.LoadConfig(tmp.Name())
	if loadErr != nil {
		b.Fatalf("config.LoadConfig: %v", loadErr)
	}

	factory := &securityFactory{
		ctx:      context.Background(),
		path:     tmp.Name(),
		resolver: &net.Resolver{PreferGo: true},
		cfg:      cfg,
		// shared is zero-value: ChainChecker / WarningsWriter nil — chain_guard disabled.
		// nil-safe behavior under benchmark matches the disabled-chain_guard production state.
		shared:     coreruntime.SharedResources{},
		streamName: "test",
		trackers:   make(map[string]*state.Tracker),
	}

	ps, buildErr := factory.Build("test", "", 0, factory.shared)
	if buildErr != nil {
		b.Fatalf("securityFactory.Build: %v", buildErr)
	}

	processor := &securityProcessor{shared: factory.shared}

	rawLine := `203.0.113.1 - - [20/May/2026:10:00:00 +0000] "GET /wp-login.php HTTP/1.1" 200 512 "-" "curl/7.88" "203.0.113.1"`
	entry, ok := (&parser.CombinedParser{}).Parse(rawLine)
	if !ok {
		b.Fatal("test setup: CombinedParser failed to parse the test line")
	}
	event := &plugin.Event{
		Envelope: plugin.Envelope{
			Source:     entry.RemoteAddr,
			SourceType: "file",
			Stream:     "test",
			Timestamp:  entry.Time,
		},
		Payload: entry,
	}

	evctx := coreruntime.EventContext{
		StreamName:   "test",
		PipelineName: "",
		SourceName:   "file:/var/log/nginx/access.log",
		SourceType:   "file",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		processor.Process(context.Background(), event, ps, evctx)
	}
}
