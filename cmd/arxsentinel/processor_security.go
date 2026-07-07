// ========================== Security processor — implements runtime.LineProcessor =========
//
//	This file is a VERBATIM PORT of processLine (previously in pipeline.go) into
//	the runtime.LineProcessor implementation for arx-core/pkg/runtime.
//
//	WHAT IS HERE:
//	  - securityState      — opaque pipeline state, passed into Process;
//	                        lives from Build() until Reload() (or pipeline end).
//	  - securityProcessor  — wrapper type around state with an importable
//	                        processor; implements runtime.LineProcessor (the
//	                        factory reuses it).
//	  - Process()          — verbatim port of processLine; one line per call.
//
//	CRITICAL: the byte-for-byte processing logic matches the original. No
//	security-domain improvements or optimizations. The 135/0 integration test
//	is the gate.
//
//	WHAT IS NOT HERE:
//	  - sinks: owned by the engine via StreamSpec.Pipelines[i].Sinks.
//	  - sources: same.
//	  - tracker-GC: started by the factory once per group.
//
//	CONNECTION TO DECISIONS.md (Flow 081):
//	  - state.Scorer/Tracker/Matcher/Verifier live on the Product side
//	    (DECISION Q1/Q2).
//	  - The engine itself writes to sinks and counts events (engine.go Phase 2).
//	  - SourceName/SourceType — the engine delivers them through EventContext.
package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/mr-addams/arx-core/pkg/parser"
	"github.com/mr-addams/arx-core/pkg/plugin"
	coreruntime "github.com/mr-addams/arx-core/pkg/runtime"
	corechaincheck "github.com/mr-addams/arxsentinel/internal/core/chaincheck"
	"github.com/mr-addams/arxsentinel/internal/core/output"
	"github.com/mr-addams/arxsentinel/internal/core/scorer"
	"github.com/mr-addams/arxsentinel/internal/core/state"
	"github.com/mr-addams/arxsentinel/internal/core/whitelist"
	"github.com/mr-addams/arxsentinel/internal/sys/utils"
	"github.com/mr-addams/arxsentinel/internal/threat"
	"github.com/mr-addams/arxsentinel/pkg/processorplugins/waf"
)

// ── securityState — opaque ProcessorState passed from factory.Build into Process ++++++++

// securityState holds the long-lived dependencies shared by Process().
// It is recreated on SIGHUP-reload (factory.Reload): Scorer and Matcher are
// replaced; Tracker and Verifier survive reload (shared per group).
// FakeBotScore and DNSVerifyTimeout reflect the current config.
//
// Sinks and SourceName/SourceType are NOT stored: sinks live in
// engine.StreamSpec; SourceName/SourceType are delivered by the engine
// through EventContext.
type securityState struct {
	StreamName   string
	PipelineName string
	PipelineIdx  int
	Tracker      *state.Tracker
	Scorer       *scorer.Scorer
	Matcher      *whitelist.Matcher
	Verifier     *whitelist.Verifier
	// Waf is an optional rule-engine plugin. nil → WAF gate is skipped
	// (default behaviour for pipelines without a `processors:` block). Built
	// once in securityFactory.Build; rebuilt on Reload (mirrors Scorer rebuild).
	Waf              *waf.WafProcessor
	FakeBotScore     int
	DNSVerifyTimeout time.Duration
	// RawForward (Flow 093) — mirrors PipelineConfig.RawForward. When true,
	// Process bypasses detection/scoring entirely and forwards every line
	// as-is (see the RawForward branch near the top of Process).
	RawForward bool
	// shared (runtime.SharedResources any) — read via processor.shared, not stored on the state.
}

// Compile-time guarantee: securityProcessor satisfies runtime.LineProcessor.
var _ coreruntime.LineProcessor = (*securityProcessor)(nil)

// ── securityProcessor — implementation of runtime.LineProcessor +++++++++++++++++++++++++++++++++++

// securityProcessor implements runtime.LineProcessor. Process() is a verbatim port
// of processLine. State is read from processor fields + the passed-in securityState +
// processor.shared (for ChainChecker / WarningsWriter type-asserts).
//
// metrics callbacks are taken from processor.shared.MetricsCallbacks (nil-safe).
type securityProcessor struct {
	shared coreruntime.SharedResources
}

// Process — VERBATIM PORT of processLine from the old pipeline.go (lines 374–500).
// Step structure and order are identical to the original; the only edits are the
// pipe.X → st.X / processor.shared.X substitutions (see DECISIONS.md).
//
// runtime.LineProcessor contract:
//   - action.Skip=true → line is dropped (not our case);
//   - action.Payload != nil → engine writes to sinks and increments eventCount
//     (engine does this itself, see dispatchEntry).
//   - action.Payload == nil → line passed through normally, no events.
//
// Metrics (RecordLine / RecordInputLine) are called by the engine itself BEFORE
// Process. Our job is RecordThreat + RecordDetectorHit, which Process knows
// semantically.
func (p *securityProcessor) Process(
	ctx context.Context,
	event *plugin.Event,
	ps coreruntime.ProcessorState,
	evctx coreruntime.EventContext,
) coreruntime.Action {
	// Defensive type-assert: must always succeed, because factory.Build returns *securityState.
	st, ok := ps.(*securityState)
	if !ok {
		return coreruntime.Action{Skip: true}
	}

	// Phase 2.2 (Flow 083): the runtime contract carries *plugin.Event; the
	// payload is parser-owned. We unwrap once here and reuse the LogEntry
	// throughout the existing verbatim port.
	entry := parser.UnwrapLogEntry(event)

	// Take copies of fields to avoid data races on Reload (engine swaps ps).
	// Using local copies in Process is a standard trick for in-place reload.
	streamName := st.StreamName
	pipelineName := st.PipelineName
	fakeBotScore := st.FakeBotScore
	dnsVerifyTimeout := st.DNSVerifyTimeout
	matcher := st.Matcher
	verifier := st.Verifier
	tracker := st.Tracker
	scorerRef := st.Scorer
	sourceName := evctx.SourceName
	sourceType := evctx.SourceType

	// RawForward (Flow 093): Distributed NCS's raw-forward collector mode.
	// Bypasses detection/scoring/whitelisting entirely — every line is
	// forwarded to Outputs unscored (Level left empty; there is no verdict
	// yet, the remote node's own detector chain produces one). Checked
	// before chain-integrity / whitelist / tracker / scoring so none of
	// that state is touched for a pipeline whose only job is forwarding.
	if st.RawForward {
		return coreruntime.Action{
			Payload: &plugin.Event{
				Envelope: plugin.Envelope{
					Source:     sourceName,
					SourceType: sourceType,
					Stream:     streamName,
					Timestamp:  entry.Time,
				},
				Payload: entry,
			},
		}
	}

	// Metrics callbacks — a snapshot of the struct (atomic read of the pointer field via copy).
	mc := p.shared.MetricsCallbacks

	utils.Log("PARSER", fmt.Sprintf("%s %s %s %d",
		entry.RealIP, entry.Method, entry.Path, entry.Status,
	), "debug")

	// ── Chain integrity check ─────────────────────────────────────────────────────────
	// Engine-asserts ChainChecker / WarningsWriter from processor.shared (any → concrete).
	// nil → chain_guard disabled, skip the step.
	if cc, ok := p.shared.ChainChecker.(*corechaincheck.Checker); cc != nil && ok {
		if ww, ok := p.shared.WarningsWriter.(*output.WarningsWriter); ww != nil && ok {
			if result := cc.Check(entry.RemoteAddr); result != nil {
				_ = ww.WriteChainWarning(result, sourceName)
				utils.Log("CHAIN_WARN",
					fmt.Sprintf("%s-ip-as-client ip=%s cidr=%s source=%s",
						result.Kind, result.IP, result.MatchedCIDR, sourceName),
					"warning")
			}
		}
	}

	// ── Step 1: custom whitelist early-exit ──────────────────────────────────────────
	if matcher.IsWhitelistedIP(entry.RealIP) || matcher.IsWhitelistedUA(entry.UserAgent) || matcher.IsWhitelistedPath(entry.Path) {
		utils.Log("WHITELIST", "skipping via custom whitelist: "+entry.RealIP, "debug")
		return coreruntime.Action{}
	}

	// ── Step 1b: WAF rule-engine gate (signature-based, pre-state) ──────────────────
	// Runs AFTER whitelist (operator-explicit whitelist cannot be overridden by WAF)
	// and BEFORE bot verify (cheap signature check before expensive DNS verify).
	// WAF acts on the raw request signature — tracker.Update hasn't run yet, so
	// the IP-state hasn't accumulated history. WAF-tag sets event.Envelope.Level,
	// which is later overwritten by securityProcessor's own threat event below —
	// the tag's *score signal* via ScoreFn is the persistent contribution.
	if st.Waf != nil {
		wafEv, wafErr := st.Waf.Process(ctx, event)
		if wafErr != nil || wafEv == nil {
			// wafErr: ctx cancellation (skip); wafEv == nil: drop-rule fired (gate event out).
			// Either way — do not emit a threat event; engine drops the line.
			return coreruntime.Action{}
		}
		// tag or pass — replace event with WAF-returned (Level may be set for tag).
		event = wafEv
	}

	// ── Steps 2–3: bot detection and verification ────────────────────────────────────
	isFakeBot := false
	var exemptSet map[string]struct{}
	if _, botCfg, matched := matcher.MatchBot(entry.UserAgent); matched {
		verifyCtx, cancelVerify := context.WithTimeout(ctx, dnsVerifyTimeout)
		verified, fake := verifier.Verify(verifyCtx, entry.RealIP, botCfg)
		cancelVerify()
		if verified {
			utils.Log("WHITELIST", "skipping: verified bot "+entry.RealIP, "debug")
			return coreruntime.Action{}
		}
		isFakeBot = fake

		if !verified && !isFakeBot && matched && len(botCfg.ExemptDetectors) > 0 {
			exemptSet = make(map[string]struct{}, len(botCfg.ExemptDetectors))
			for _, name := range botCfg.ExemptDetectors {
				exemptSet[name] = struct{}{}
			}
			utils.Log("WHITELIST", fmt.Sprintf("ua_only bot %s: exempt detectors %v", entry.RealIP, botCfg.ExemptDetectors), "debug")
		}
	}

	// ── Step 4: IP state tracking ─────────────────────────────────────────────────────
	ipState := tracker.Update(entry)

	// ── Step 4b: fake bot penalty ─────────────────────────────────────────────────────
	if isFakeBot {
		ipState.SetScore(ipState.GetScore()+fakeBotScore, time.Now())
		utils.Log("WHITELIST", fmt.Sprintf("fake bot %s +%d (fake bot score)", entry.RealIP, fakeBotScore), "warn")
	}

	// ── Scoring ───────────────────────────────────────────────────────────────────────
	level, score, modules, reason := scorerRef.Evaluate(ipState, entry, exemptSet)

	if level == "" {
		return coreruntime.Action{}
	}

	// RecordThreat metric (nil-safe).
	if mc != nil && mc.RecordThreat != nil {
		mc.RecordThreat(streamName, pipelineName, level)
	}
	for _, mod := range modules {
		if mc != nil && mc.RecordDetectorHit != nil {
			mc.RecordDetectorHit(streamName, pipelineName, mod)
		}
	}

	threat := threat.ThreatEvent{
		Timestamp:  time.Now().UTC(),
		Level:      level,
		Stream:     streamName,
		Source:     sourceName,
		SourceType: sourceType,
		IP:         entry.RealIP,
		Score:      score,
		Modules:    modules,
		Reason:     reason,
	}
	utils.Log("THREAT", fmt.Sprintf("%s score=%d modules=%s reason=%q",
		entry.RealIP, score, strings.Join(modules, ","), reason), "warning")

	// Engine (dispatchEntry) does sink.Write + RecordOutputEvent itself;
	// eventCount.Add(1) is performed by the engine only when level == "THREAT".
	// Gate B (Flow 083): Action carries a generic *plugin.Event whose
	// Payload is the product-owned *threat.ThreatEvent (live in
	// internal/threat). The engine reads Payload.Envelope.Level for
	// metrics — we set it here.
	return coreruntime.Action{
		Payload: &plugin.Event{
			Envelope: plugin.Envelope{
				Source:     sourceName,
				SourceType: sourceType,
				Stream:     streamName,
				Level:      level,
				Timestamp:  threat.Timestamp,
			},
			Payload: &threat,
		},
	}
}

// RecordLine metric (on EVERY line, before Process) — the engine calls it
// itself (see engine.go dispatchEntry). Here we only note that these metrics
// in the RecordLine callback already cover the product-level calls of
// metrics.RecordLine + metrics.RecordInputLine — main.go does this in the
// MetricsCallbacks adapter.
//
// RecordOutputEvent is called by the engine upon sink.Write — the main.go
// adapter inside the callback invokes sinkTypeFromName(sink.Name) to compute
// sinkType.
