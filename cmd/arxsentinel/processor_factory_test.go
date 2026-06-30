//go:build !arx_tag

package main

import (
	"strings"
	"testing"

	"github.com/mr-addams/arxsentinel/internal/core/state"
	"github.com/mr-addams/arxsentinel/internal/sys/config"
	"github.com/mr-addams/arxsentinel/pkg/processorplugins/waf"
)

// TestBuildWafProcessor_NilProcessors verifies that a nil slice means "no WAF
// configured" — buildWafProcessor returns (nil, nil) and the pipeline runs without
// the WAF gate. This is the expected state for configs created before H11.
func TestBuildWafProcessor_NilProcessors(t *testing.T) {
	nopLog := func(_, _, _ string) {}
	tracker := state.NewTracker(loadMinimalConfig(t), nopLog)

	res, err := buildWafProcessor(nil, tracker, 100)
	if err != nil {
		t.Fatalf("buildWafProcessor(nil): want nil error, got %v", err)
	}
	if res != nil {
		t.Fatalf("buildWafProcessor(nil): want nil result, got %v", res)
	}
}

// TestBuildWafProcessor_EmptyProcessors verifies that an empty (non-nil) slice
// behaves exactly like nil — no WAF gate is installed.
func TestBuildWafProcessor_EmptyProcessors(t *testing.T) {
	nopLog := func(_, _, _ string) {}
	tracker := state.NewTracker(loadMinimalConfig(t), nopLog)

	res, err := buildWafProcessor([]config.ProcessorConfig{}, tracker, 100)
	if err != nil {
		t.Fatalf("buildWafProcessor(empty): want nil error, got %v", err)
	}
	if res != nil {
		t.Fatalf("buildWafProcessor(empty): want nil result, got %v", res)
	}
}

// TestBuildWafProcessor_NoWafEntry verifies that a non-WAF plugin entry is ignored
// without falling through to the processor registry. buildWafProcessor only looks for
// Plugin == "waf" and returns (nil, nil) for every other plugin name.
func TestBuildWafProcessor_NoWafEntry(t *testing.T) {
	nopLog := func(_, _, _ string) {}
	tracker := state.NewTracker(loadMinimalConfig(t), nopLog)

	processors := []config.ProcessorConfig{{Plugin: "other_plugin", Params: nil}}
	res, err := buildWafProcessor(processors, tracker, 100)
	if err != nil {
		t.Fatalf("buildWafProcessor(other): want nil error, got %v", err)
	}
	if res != nil {
		t.Fatalf("buildWafProcessor(other): want nil result, got %v", res)
	}
}

// TestBuildWafProcessor_EmptyRules_FailFast verifies fail-fast behaviour: a WAF
// entry whose waf_config has no rules must return an error in buildWafProcessor,
// surfacing the misconfiguration at startup rather than silently running with an
// empty ruleset.
func TestBuildWafProcessor_EmptyRules_FailFast(t *testing.T) {
	nopLog := func(_, _, _ string) {}
	tracker := state.NewTracker(loadMinimalConfig(t), nopLog)

	params := map[string]any{"waf_config": waf.Config{Rules: nil}}
	processors := []config.ProcessorConfig{{Plugin: "waf", Params: params}}
	res, err := buildWafProcessor(processors, tracker, 100)
	if err == nil {
		t.Fatal("buildWafProcessor(empty rules): want error, got nil")
	}
	if res != nil {
		t.Fatalf("buildWafProcessor(empty rules): want nil result on error, got %v", res)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "rule") {
		t.Errorf("buildWafProcessor(empty rules) error should mention rule, got: %v", err)
	}
}

// TestBuildWafProcessor_ValidConfig verifies the happy path: a single WAF entry
// with a valid rule produces a non-nil *waf.WafProcessor and no error.
func TestBuildWafProcessor_ValidConfig(t *testing.T) {
	nopLog := func(_, _, _ string) {}
	tracker := state.NewTracker(loadMinimalConfig(t), nopLog)

	wafCfg := waf.Config{
		Rules: []waf.RuleConfig{{
			Name:       "test_drop",
			Expression: `http.path contains "/test"`,
			Action:     "drop",
		}},
	}
	params := map[string]any{"waf_config": wafCfg}
	processors := []config.ProcessorConfig{{Plugin: "waf", Params: params}}
	res, err := buildWafProcessor(processors, tracker, 100)
	if err != nil {
		t.Fatalf("buildWafProcessor(valid): %v", err)
	}
	if res == nil {
		t.Fatal("buildWafProcessor(valid): want non-nil result, got nil")
	}
}
