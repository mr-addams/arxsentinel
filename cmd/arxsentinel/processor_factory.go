// ========================== Security factory — implements LineProcessorFactory =============
//
//	This file is the Product-side implementation of runtime.LineProcessorFactory.
//
//	WHAT IS HERE:
//	  - securityFactory      — per-pipeline state factory; implements both
//	                           interfaces (LineProcessorFactory + LineProcessor —
//	                           this is intentional: engine.Run performs a type
//	                           assertion).
//	  - Build()              — constructs matcher / verifier / scorer / tracker;
//	                           starts the GC goroutine once per tracker group.
//	  - Reload()             — SIGHUP-reload: re-reads config, rebuilds matcher
//	                           + scorer + detectors; tracker is reused.
//
//	CRITICAL: Build/Reload have side effects (GC start, file reads). Do not
//	modify without revisiting DECISIONS.md Flow 081.
//
//	ONE factory per stream: main.go creates one securityFactory instance per
//	cfg.Streams[i] and passes it to runtime.Run (the engine performs a type
//	assertion to LineProcessor — the factory must implement both interfaces).
//
//	CONNECTION TO DECISIONS.md:
//	  - TrackerGroup: Pipeline.TrackerGroup → resolveTrackerGroup; shared
//	    inside the factory via the trackers map[string]*state.Tracker
//	    (mutex guarded).
//	  - GC: once per tracker (not per pipeline) — original semantics, see
//	    securityFactory.getOrCreateTracker.
//	  - Sources/Sinks are NOT built here — runtime_adapter.go does that and
//	    passes them to the engine through StreamSpec.Pipelines[i].Sinks/Sources.
package main

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/mr-addams/arx-core/pkg/plugin"
	coreruntime "github.com/mr-addams/arx-core/pkg/runtime"
	"github.com/mr-addams/arxsentinel/internal/core/blocklist"
	"github.com/mr-addams/arxsentinel/internal/core/scorer"
	"github.com/mr-addams/arxsentinel/internal/core/state"
	"github.com/mr-addams/arxsentinel/internal/core/whitelist"
	"github.com/mr-addams/arxsentinel/internal/sys/config"
	"github.com/mr-addams/arxsentinel/internal/sys/utils"
	"github.com/mr-addams/arxsentinel/pkg/processorplugins/waf"
	"gopkg.in/yaml.v3"
)

// ++++++++++++++++++++++++++ securityFactory — Product-side factory ++++++++++++++++++++++++

// securityFactory implements runtime.LineProcessorFactory + runtime.LineProcessor.
//
// One factory instance per stream. main.go creates it BEFORE runtime.Run and
// passes it to the engine as `factory`. The engine performs a type assertion:
//   - LineProcessorFactory — for Build/Reload;
//   - LineProcessor        — for Process (factory.Process delegates to a
//     securityProcessor instance carrying shared).
//
// shared is runtime.SharedResources (opaque). Security-domain fields
// (ChainChecker / WarningsWriter / BlocklistManager) are reachable through a
// type assertion.
type securityFactory struct {
	ctx      context.Context // app context — for tracker.RunGC
	path     string          // path to config.yaml — for Reload
	ipCache  *whitelist.IPCache
	resolver *net.Resolver

	cfg   config.Config // snapshot at factory creation time; Reload updates it
	cfgMu sync.Mutex    // guard for cfg across Reload (multiple pipelines re-reading)

	streamName    string
	streamNameIdx int

	// Per-stream tracker cache by group. The same *state.Tracker is shared
	// between pipelines of one group — original semantics (pipeline.go:139-146
	// buildTrackerGroups).
	trackers  map[string]*state.Tracker
	trackerMu sync.Mutex

	// shared is immutable after creation (we only read from it). It is copied
	// into securityProcessor.Process via &securityProcessor{shared: f.shared}.
	shared coreruntime.SharedResources
}

// Compile-time guarantees: the factory satisfies BOTH runtime interfaces.
var (
	_ coreruntime.LineProcessorFactory = (*securityFactory)(nil)
	_ coreruntime.LineProcessor        = (*securityFactory)(nil)
)

// ── Process — delegates to securityProcessor.Process ++++++++++++++++++++++++++++++++++++++++

// Process is the entry point for engine.dispatchEntry. It creates a
// securityProcessor (carrying shared) on the fly and delegates processing to
// it.
//
// A NEW securityProcessor is allocated on every call — this is a cheap
// allocation (1 shared pointer field); it does not create GC pressure
// (escape analysis inlines the value).
func (f *securityFactory) Process(
	ctx context.Context,
	event *plugin.Event,
	ps coreruntime.ProcessorState,
	evctx coreruntime.EventContext,
) coreruntime.Action {
	return (&securityProcessor{shared: f.shared}).Process(ctx, event, ps, evctx)
}

// ── Build — construct per-pipeline ProcessorState ++++++++++++++++++++++++++++++++++++++++

// Build constructs the per-pipeline ProcessorState.
// It is called by arx-core/pkg/runtime engine.runPipeline ONCE at pipeline start.
// Inside:
//  1. Resolve pipeCfg by stream/pipe/idx (snapshot cfg under cfgMu).
//  2. Matcher, Verifier, Scorer + detectors (via buildPipelineDetectors).
//  3. Tracker: shared per group; created under trackerMu if not yet present.
//  4. Start the GC goroutine ONCE per unique tracker (ctx = f.ctx).
func (f *securityFactory) Build(
	streamName, pipeName string,
	pipeIdx int,
	shared coreruntime.SharedResources,
) (coreruntime.ProcessorState, error) {
	f.cfgMu.Lock()
	cfg := f.cfg
	f.cfgMu.Unlock()

	// Resolve stream/pipe configs. For Build there is no old state — fall back
	// to pipeName/idx from the input parameters; normally cfg.Streams contains
	// the requested stream.
	streamCfg, ok := findStreamCfg(cfg, streamName)
	if !ok {
		return nil, fmt.Errorf("stream %q not found in config", streamName)
	}
	pipeCfg := findPipelineCfg(streamCfg, pipeName, pipeIdx, streamCfg.Pipelines[pipeIdx])

	// Matcher may fail on a config error.
	matcher, err := whitelist.NewMatcher(cfg.Whitelist)
	if err != nil {
		return nil, fmt.Errorf("whitelist init error: %w", err)
	}

	// Verifier uses the shared IPCache (DNS results are not pipeline-specific).
	verifier := whitelist.NewVerifier(f.ipCache, f.resolver, utils.Log)

	// bridgeShared expects the old cmd/arxsentinel SharedResources (used inside
	// buildPipelineDetectors). Convert runtime.SharedResources → old.
	oldShared := bridgeRuntimeShared(shared)
	detectors := buildPipelineDetectors(f.ctx, cfg, pipeCfg, oldShared)
	scorerRef := scorer.NewScorer(cfg.Scoring, detectors, utils.Log)

	// Tracker is shared per group. The same *state.Tracker between pipelines
	// of one group (DECISIONS.md Flow 081, original buildTrackerGroups semantics).
	group := resolveTrackerGroup(pipeCfg)
	tracker := f.getOrCreateTracker(group, cfg)

	// WAF processor — optional, nil-safe. Built from the first `plugin: waf`
	// entry in pipeCfg.Processors; empty list → Waf=nil, WAF gate is a no-op.
	// ScoreFn closure binds the per-group tracker so WAF can signal score
	// deltas directly into the same IPState securityProcessor consults later.
	wafProc, err := buildWafProcessor(pipeCfg.Processors, tracker, cfg.Scoring.BanThreshold)
	if err != nil {
		return nil, fmt.Errorf("waf init error: %w", err)
	}

	return &securityState{
		StreamName:       streamName,
		PipelineName:     pipeName,
		PipelineIdx:      pipeIdx,
		Tracker:          tracker,
		Scorer:           scorerRef,
		Matcher:          matcher,
		Verifier:         verifier,
		Waf:              wafProc,
		FakeBotScore:     cfg.Whitelist.FakeBotScore,
		DNSVerifyTimeout: time.Duration(cfg.Whitelist.DNSVerifyTimeout),
		RawForward:       pipeCfg.RawForward,
	}, nil
}

// ── Reload — SIGHUP-equivalent reload +++++++++++++++++++++++++++++++++++++++++++++++++++++

// Reload is a SIGHUP-equivalent reload. It returns a NEW *securityState; the
// engine swaps it in atomically. Tracker and Verifier survive reload (shared
// per group; their state (ban list, DNS cache) must survive reload).
//
// The steps mirror the original reload block in runPipeline, which was moved
// into arx-core/pkg/runtime (engine.runPipeline, case <-reloadCh).
func (f *securityFactory) Reload(
	old coreruntime.ProcessorState,
	ctx context.Context,
) (coreruntime.ProcessorState, error) {
	oldState, ok := old.(*securityState)
	if !ok {
		return nil, fmt.Errorf("Reload: unexpected state type %T", old)
	}

	newCfg, err := config.LoadConfig(f.path)
	if err != nil {
		return nil, fmt.Errorf("SIGHUP reload error: %w", err)
	}

	newMatcher, err := whitelist.NewMatcher(newCfg.Whitelist)
	if err != nil {
		return nil, fmt.Errorf("SIGHUP whitelist error: %w", err)
	}

	// Look up the updated stream config by name; fall back to the old one if removed.
	newStreamCfg, ok := findStreamCfg(newCfg, oldState.StreamName)
	if !ok {
		newStreamCfg = streamConfigFromOld(oldState)
	}
	newPipeCfg := findPipelineCfg(newStreamCfg, oldState.PipelineName, oldState.PipelineIdx,
		oldPipeConfigFromOld(oldState))

	// Update the cfg snapshot under the mutex — subsequent Build calls see the fresh cfg.
	f.cfgMu.Lock()
	f.cfg = newCfg
	f.cfgMu.Unlock()

	// detectors + Scorer — rebuild.
	oldShared := bridgeRuntimeShared(f.shared)
	detectors := buildPipelineDetectors(ctx, newCfg, newPipeCfg, oldShared)
	scorerRef := scorer.NewScorer(newCfg.Scoring, detectors, utils.Log)

	// Tracker.Reconfigure adapts the inner state (windows, intervals) to the
	// new config while preserving IPState data.
	oldState.Tracker.Reconfigure(newCfg)

	// WAF — rebuild from new cfg (rules may have changed; RuleSet is read-only
	// compiled, so a fresh WafProcessor is required for new rules). Tracker
	// is reused → ScoreFn closure binds the same tracker (correct, same group).
	wafProc, err := buildWafProcessor(newPipeCfg.Processors, oldState.Tracker, newCfg.Scoring.BanThreshold)
	if err != nil {
		return nil, fmt.Errorf("waf reload error: %w", err)
	}

	utils.Log("CONFIG", fmt.Sprintf("%s: SIGHUP config reloaded",
		pipelineLogTag(oldState.StreamName, oldState.PipelineName)), "info")

	return &securityState{
		StreamName:       oldState.StreamName,
		PipelineName:     oldState.PipelineName,
		PipelineIdx:      oldState.PipelineIdx,
		Tracker:          oldState.Tracker,
		Scorer:           scorerRef,
		Matcher:          newMatcher,
		Verifier:         oldState.Verifier,
		Waf:              wafProc,
		FakeBotScore:     newCfg.Whitelist.FakeBotScore,
		DNSVerifyTimeout: time.Duration(newCfg.Whitelist.DNSVerifyTimeout),
		RawForward:       newPipeCfg.RawForward,
	}, nil
}

// ── Helpers (private) ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

// getOrCreateTracker returns the existing tracker for the group or creates a
// new one and starts its GC goroutine ONCE.
//
// trackerMu protects the map from concurrent first-time creation across
// pipelines of the same group (a startup race if engine.Run launches pipeline
// goroutines in parallel).
func (f *securityFactory) getOrCreateTracker(group string, cfg config.Config) *state.Tracker {
	f.trackerMu.Lock()
	defer f.trackerMu.Unlock()

	if t, ok := f.trackers[group]; ok {
		return t
	}
	t := state.NewTracker(cfg, utils.Log)
	f.trackers[group] = t
	// GC runs ONCE per tracker (DECISIONS.md Flow 081). f.ctx is appCtx, so
	// SIGTERM/SIGINT cancellation stops the GC.
	go t.RunGC(f.ctx, time.Duration(cfg.State.GCInterval))
	return t
}

// bridgeRuntimeShared converts runtime.SharedResources into the legacy
// cmd/arxsentinel SharedResources for buildPipelineDetectors. The latter
// accepts the old type via bridgeShared (builders.go) — Phase 4 will unify
// the signature.
//
// A type assertion on the concrete *blocklist.Manager is sufficient here:
// bridgeShared (builders.go) uses ONLY BlocklistManager, ChainChecker and
// WarningsWriter — buildPipelineDetectors does not need them.
func bridgeRuntimeShared(shared coreruntime.SharedResources) SharedResources {
	out := SharedResources{}
	if mgr, ok := shared.BlocklistManager.(*blocklist.Manager); ok {
		out.BlocklistManager = mgr
	}
	return out
}

// findStreamCfg locates a StreamConfig by name. Used for Reload (no fallback).
func findStreamCfg(cfg config.Config, name string) (config.StreamConfig, bool) {
	for _, s := range cfg.Streams {
		if s.Name == name {
			return s, true
		}
	}
	return config.StreamConfig{}, false
}

// streamConfigFromOld reconstructs a minimal StreamConfig from the old state —
// needed when the new cfg has removed the stream. findPipelineCfg in Reload
// uses the old pipeCfg (old PipeConfig) as a fallback — the real pipeCfg
// cannot be recovered in that case, hence the fallback.
func streamConfigFromOld(old *securityState) config.StreamConfig {
	return config.StreamConfig{Name: old.StreamName}
}

// oldPipeConfigFromOld is a stub for the findPipelineCfg fallback. It is used
// only when the new stream does not contain the requested pipeline
// (sighup-remove). It is a minimal stub — the real pipeCfg cannot be recovered
// in that case.
func oldPipeConfigFromOld(old *securityState) config.PipelineConfig {
	return config.PipelineConfig{Name: old.PipelineName}
}

// buildWafProcessor scans pipeCfg.Processors for the first entry with
// plugin=="waf" and returns a compiled *waf.WafProcessor, or nil if no WAF
// is configured. Shared by Build() and Reload() — the only difference between
// the two calls is the cfg.Processors slice and tracker reference.
//
// Implementation note: ProcessorConfig.Params is `map[string]any` after yaml
// parsing — yaml round-trip converts the `waf_config` sub-key into a typed
// waf.Config struct (yaml.v3 → waf.Config.Unmarshal). This is the same
// convention used elsewhere in arxsentinel for plugin-specific typed config
// (see DetectorConfig.Params round-trip in builders.go).
//
// ScoreFn is bound here so the closure captures the per-group *state.Tracker
// — WAF fires scoreFn(ip, delta) on drop / tag:<label> hits and the deltas
// land in the same IPState that securityProcessor's scorer reads later.
// banThreshold is used as DropScore fallback when the waf_config block does
// not set DropScore explicitly — keeps WAF ban-coordination in sync with
// cfg.Scoring.BanThreshold without operator duplication.
func buildWafProcessor(processors []config.ProcessorConfig, tracker *state.Tracker, banThreshold int) (*waf.WafProcessor, error) {
	for _, pc := range processors {
		if pc.Plugin != "waf" {
			continue
		}
		// `waf_config` may be absent (rules-only config with all knobs defaulted)
		// or typed (rebuilt config from a previous run).
		rawCfg, ok := pc.Params["waf_config"]
		if !ok {
			return nil, fmt.Errorf("waf: plugin entry missing required key %q", "waf_config")
		}
		var wafCfg waf.Config
		switch v := rawCfg.(type) {
		case waf.Config:
			// Already typed — direct assignment, no round-trip needed.
			wafCfg = v
		case map[string]any:
			// yaml-parsed form: marshal→unmarshal to populate the typed struct.
			buf, err := yaml.Marshal(v)
			if err != nil {
				return nil, fmt.Errorf("waf: marshal waf_config: %w", err)
			}
			if err := yaml.Unmarshal(buf, &wafCfg); err != nil {
				return nil, fmt.Errorf("waf: unmarshal waf_config: %w", err)
			}
		default:
			return nil, fmt.Errorf("waf: waf_config must be a map or waf.Config (got %T)", rawCfg)
		}
		// DropScore fallback: align WAF drop-weight with the global ban
		// threshold when the operator didn't set DropScore explicitly.
		if wafCfg.DropScore == 0 && banThreshold > 0 {
			wafCfg.DropScore = banThreshold
		}
		// ScoreFn closure — pipeline-single-writer model (tracker.go:75).
		// Safe: Update and ScoreFn run in the same goroutine, so the
		// returned *IPState pointer isn't concurrently mutated.
		wafCfg.ScoreFn = func(ip string, delta int) {
			if st := tracker.GetState(ip); st != nil {
				st.SetScore(st.GetScore()+delta, time.Now())
			}
		}
		return waf.NewWafProcessor(wafCfg)
	}
	// No WAF entry — pipeline runs without the rule-engine gate.
	return nil, nil
}
