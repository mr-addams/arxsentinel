//go:build !arx_tag

package main

import (
	"context"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/mr-addams/arxsentinel/internal/core/scorer"
	"github.com/mr-addams/arxsentinel/internal/core/state"
	"github.com/mr-addams/arxsentinel/internal/core/whitelist"
	"github.com/mr-addams/arxsentinel/internal/sys/config"
	"github.com/mr-addams/arxsentinel/internal/sys/utils"
	"github.com/mr-addams/arx-core/pkg/parser"
)

// TestBuildPipelineDetectors_ExplicitSubset verifies that when pipeCfg.Detectors is non-nil,
// only the listed detectors are built — not all globally registered ones.
func TestBuildPipelineDetectors_ExplicitSubset(t *testing.T) {
	cfg := loadMinimalConfig(t)

	pipeCfg := config.PipelineConfig{
		Name: "api",
		Detectors: map[string]config.DetectorConfig{
			"probe": {Enabled: true, Params: map[string]interface{}{"score": 25}},
			"rate":  {Enabled: true, Params: map[string]interface{}{"threshold": 100}},
		},
	}

	// Silence detector config logging during the test.
	// t.Cleanup is used (vs defer) to make the intent explicit — t.Cleanup runs
	// after all subtests complete and after t.Fatalf() via runtime.Goexit()).
	if err := utils.Init(false, false, "", ""); err != nil {
		t.Fatalf("utils.Init: %v", err)
	}
	t.Cleanup(utils.Close)

	detectors := buildPipelineDetectors(context.Background(), cfg, pipeCfg, SharedResources{})

	if len(detectors) != 2 {
		t.Fatalf("expected 2 detectors (probe, rate), got %d", len(detectors))
	}
	names := make([]string, len(detectors))
	for i, d := range detectors {
		names[i] = d.Name()
	}
	sort.Strings(names)
	if names[0] != "probe" || names[1] != "rate" {
		t.Errorf("expected detectors [probe rate], got %v", names)
	}
}

// TestBuildPipelineDetectors_DisabledSkipped verifies that disabled detectors
// in the explicit list are not included in the result.
func TestBuildPipelineDetectors_DisabledSkipped(t *testing.T) {
	cfg := loadMinimalConfig(t)

	pipeCfg := config.PipelineConfig{
		Name: "api",
		Detectors: map[string]config.DetectorConfig{
			"probe": {Enabled: true},
			"rate":  {Enabled: false}, // disabled — must be excluded
		},
	}

	if err := utils.Init(false, false, "", ""); err != nil {
		t.Fatalf("utils.Init: %v", err)
	}
	t.Cleanup(utils.Close)

	detectors := buildPipelineDetectors(context.Background(), cfg, pipeCfg, SharedResources{})

	if len(detectors) != 1 {
		t.Fatalf("expected 1 detector (probe only), got %d", len(detectors))
	}
	if detectors[0].Name() != "probe" {
		t.Errorf("expected probe detector, got %q", detectors[0].Name())
	}
}

// TestPipeline_FakeBotStillCaught verifies that a fake ClaudeBot (high request rate)
// is still caught by the rate detector even though noasset is exempted.
func TestPipeline_FakeBotStillCaught(t *testing.T) {
	cfg := loadMinimalConfig(t)
	// Low rate threshold so burst triggers quickly.
	cfg.Detectors.Rate.Threshold = 3
	cfg.Detectors.Rate.Enabled = true
	cfg.Detectors.NoAsset.Enabled = true
	cfg.Scoring.AlertThreshold = 10

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

	// Send 5 rapid requests from the same IP with ClaudeBot UA.
	// Rate threshold = 3, so after ~3 requests the rate detector fires.
	var lastScore int
	var caughtByRate bool
	now := time.Now()
	for i := range 5 {
		rawLine := fmt.Sprintf(`1.2.3.4 - - [%s] "GET /page%d HTTP/1.1" 200 512 "-" "ClaudeBot/1.0" "1.2.3.4"`,
			now.Add(time.Duration(i)*time.Second).Format("02/Jan/2006:15:04:05 -0700"), i)
		entry, ok := p.Parse(rawLine)
		if !ok {
			t.Fatalf("iteration %d: failed to parse log line", i)
		}

		_, botCfg, matched := matcher.MatchBot(entry.UserAgent)
		if !matched {
			t.Fatalf("iteration %d: ClaudeBot UA did not match", i)
		}

		ctx := context.Background()
		verified, isFakeBot := verifier.Verify(ctx, entry.RealIP, botCfg)
		if verified || isFakeBot {
			t.Fatalf("iteration %d: ua_only expected (false, false)", i)
		}

		var exemptSet map[string]struct{}
		if !verified && !isFakeBot && len(botCfg.ExemptDetectors) > 0 {
			exemptSet = make(map[string]struct{}, len(botCfg.ExemptDetectors))
			for _, name := range botCfg.ExemptDetectors {
				exemptSet[name] = struct{}{}
			}
		}

		ipState := tracker.Update(entry)
		_, score, modules, _ := sc.Evaluate(ipState, entry, exemptSet)
		lastScore = score

		for _, mod := range modules {
			if mod == "rate" {
				caughtByRate = true
			}
			if mod == "noasset" {
				t.Errorf("iteration %d: noasset fired despite exemptSet", i)
			}
		}
	}

	if !caughtByRate {
		t.Errorf("rate detector did not fire after 5 rapid ClaudeBot requests (final score=%d)", lastScore)
	}
	if lastScore <= 0 {
		t.Errorf("final score is 0 — fake bot was not caught by any detector")
	}

	t.Logf("Fake bot caught: score=%d, rate module triggered", lastScore)
}
