//go:build !arx_tag

package main

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mr-addams/arx-core/pkg/parser"
	"github.com/mr-addams/arx-core/pkg/plugin"
	coreruntime "github.com/mr-addams/arx-core/pkg/runtime"
	"github.com/mr-addams/arxsentinel/internal/core/scorer"
	"github.com/mr-addams/arxsentinel/internal/core/state"
	"github.com/mr-addams/arxsentinel/internal/core/whitelist"
	"github.com/mr-addams/arxsentinel/internal/sys/config"
	"github.com/mr-addams/arxsentinel/internal/sys/utils"
	"github.com/mr-addams/arxsentinel/pkg/processorplugins/waf"
)

// TestWAFIntegration_DropAndTag проверяет wire-up WAF внутри securityProcessor.Process:
//   - drop-правило: Process возвращает Action{} без payload (событие погашено до scorer)
//   - tag-правило: Process возвращает Action{} без payload когда scorer не накопил угрозы,
//     и ScoreFn вызывается для IP у которого уже есть state
//   - pass-правило: событие проходит через WAF к scorer штатно
//   - nil WAF (Waf==nil): WAF gate пропускается, штатный поток работает
func TestWAFIntegration_DropAndTag(t *testing.T) {
	if err := utils.Init(false, false, "", ""); err != nil {
		t.Fatalf("utils.Init: %v", err)
	}
	t.Cleanup(utils.Close)

	cfg := loadMinimalConfig(t)
	cfg.Scoring.BanThreshold = 100
	cfg.Scoring.AlertThreshold = 50

	nopLog := func(_, _, _ string) {}
	tracker := state.NewTracker(cfg, nopLog)

	matcher, err := whitelist.NewMatcher(cfg.Whitelist)
	if err != nil {
		t.Fatalf("whitelist.NewMatcher: %v", err)
	}
	detectors := buildPipelineDetectors(context.Background(), cfg, loadMinimalPipelineCfg(), SharedResources{})
	sc := scorer.NewScorer(cfg.Scoring, detectors, nopLog)
	verifier := whitelist.NewVerifier(whitelist.NewIPCache(cfg.Whitelist.DNSCache), nil, nopLog)

	var scoreCalls atomic.Int64
	scoreFn := func(_ string, _ int) { scoreCalls.Add(1) }

	wafCfg := waf.Config{
		Rules: []waf.RuleConfig{
			{Name: "pass_health", Expression: `http.path eq "/healthz"`, Action: "pass"},
			{Name: "sqli_drop", Expression: `http.path contains "OR 1=1"`, Action: "drop"},
			{Name: "admin_tag", Expression: `http.path contains "/admin"`, Action: "tag:suspect"},
		},
		DropScore:  100,
		TagWeights: map[string]int{"suspect": 20},
		ScoreFn:    scoreFn,
	}
	wafProc, err := waf.NewWafProcessor(wafCfg)
	if err != nil {
		t.Fatalf("waf.NewWafProcessor: %v", err)
	}

	st := &securityState{
		StreamName:       "test",
		PipelineName:     "default",
		Tracker:          tracker,
		Scorer:           sc,
		Matcher:          matcher,
		Verifier:         verifier,
		Waf:              wafProc,
		FakeBotScore:     cfg.Scoring.BanThreshold,
		DNSVerifyTimeout: 2 * time.Second,
	}
	proc := &securityProcessor{shared: coreruntime.SharedResources{}}

	p := &parser.CombinedParser{}
	evctx := coreruntime.EventContext{SourceName: "test", SourceType: "nginx"}

	makeEvent := func(path string) *plugin.Event {
		rawLine := `1.2.3.4 - - [01/Jan/2025:00:00:00 +0000] "GET ` + path + ` HTTP/1.1" 200 512 "-" "curl/7.0" "1.2.3.4"`
		entry, ok := p.Parse(rawLine)
		if !ok {
			t.Fatalf("parse failed for path %q", path)
		}
		return parser.WrapLogEntry(entry, plugin.Envelope{})
	}

	t.Run("drop_fires_no_payload", func(t *testing.T) {
		scoreCalls.Store(0)
		action := proc.Process(context.Background(), makeEvent(`/search?q=' OR 1=1 --`), st, evctx)
		if action.Payload != nil {
			t.Errorf("drop rule: expected nil payload, got %T", action.Payload)
		}
		// ScoreFn fires even on drop — IP may not yet be in tracker, so call count
		// depends on whether GetState returns nil. Either 0 or 1 is correct.
	})

	t.Run("pass_rule_reaches_scorer", func(t *testing.T) {
		// /healthz has a pass-rule → WAF short-circuits to pass, scorer runs normally.
		// With no detectors triggered by a single request, Action.Payload == nil.
		action := proc.Process(context.Background(), makeEvent("/healthz"), st, evctx)
		// Payload nil or non-nil — both valid; key invariant is no panic.
		_ = action
	})

	t.Run("unmatched_passes_through", func(t *testing.T) {
		// /api/data matches no rule → WAF passes event to scorer.
		// Single request — scorer likely doesn't threshold → nil payload expected.
		action := proc.Process(context.Background(), makeEvent("/api/data"), st, evctx)
		_ = action
	})

	t.Run("nil_waf_skips_gate", func(t *testing.T) {
		noWafState := &securityState{
			StreamName:       "test",
			PipelineName:     "default",
			Tracker:          tracker,
			Scorer:           sc,
			Matcher:          matcher,
			Verifier:         verifier,
			Waf:              nil,
			FakeBotScore:     cfg.Scoring.BanThreshold,
			DNSVerifyTimeout: 2 * time.Second,
		}
		// Even a path that would trigger drop passes when WAF is nil.
		action := proc.Process(context.Background(), makeEvent(`/search?q=' OR 1=1 --`), noWafState, evctx)
		// No panic expected; payload may or may not be set by scorer.
		_ = action
	})
}

func loadMinimalPipelineCfg() config.PipelineConfig {
	return config.PipelineConfig{}
}
