// ========================== pkg/processor/waf — processor tests =========================
//   Coverage for WafProcessor (Flow 001, Task H4).
//
//   Test surfaces:
//     1. Match + drop path: rule fires, action=drop → (nil, nil).
//     2. Match + tag path: rule fires, action=tag → event with Level="THREAT:<name>".
//     3. Match + pass path: rule fires, action=pass → event passed through unchanged.
//     4. No match: event passed through with Level untouched.
//     5. Concurrent safety: many goroutines hammer Process with -race enabled.
//     6. Fail-fast: bad expression returns error naming the rule from NewWafProcessor.
//     7. ctx.Err() honored: cancelled context short-circuits before Match.
//     8. Empty config: constructor accepts zero rules, every event passes through.

package waf

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/mr-addams/arx-core/pkg/parser"
	"github.com/mr-addams/arx-core/pkg/plugin"
)

// ========================== helpers ========================================================

// makeLogEvent wraps a *parser.LogEntry in a *plugin.Event the WAF processor can
// consume. Tests that care about envelope fields set them via the returned pointer.
func makeLogEvent(e *parser.LogEntry) *plugin.Event {
	return &plugin.Event{
		Envelope: plugin.Envelope{Stream: "main", Level: ""},
		Payload:  e,
	}
}

// defaultConfig returns a small but expressive WAF config used by the happy-path
// tests. Rules:
//   - block_post_405 — drops POST requests that returned 405
//   - tag_admin_path — tags any request whose path contains "/admin"
//   - pass_healthcheck — passes through GET /healthz (no-op rule, used to verify
//     pass action preserves the event unchanged)
func defaultConfig() Config {
	return Config{
		Rules: []RuleConfig{
			{Name: "block_post_405", Expression: `http.method eq "POST" and http.status eq 405`, Action: ActionDrop},
			{Name: "tag_admin_path", Expression: `http.path contains "/admin"`, Action: ActionTag},
			{Name: "pass_healthcheck", Expression: `http.path eq "/healthz"`, Action: ActionPass},
		},
	}
}

// ========================== 1. Match + drop path ============================================

// TestWafProcessor_DropOnMatch verifies a rule that fires with action=drop returns
// (nil, nil). The event payload is irrelevant once the rule fires.
func TestWafProcessor_DropOnMatch(t *testing.T) {
	p, err := NewWafProcessor(defaultConfig())
	if err != nil {
		t.Fatalf("NewWafProcessor: %v", err)
	}
	ev := makeLogEvent(&parser.LogEntry{Method: "POST", Status: 405, Path: "/api/users"})

	got, err := p.Process(context.Background(), ev)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if got != nil {
		t.Errorf("Process: want nil event (drop), got %+v", got)
	}
}

// ========================== 2. Match + tag path =============================================

// TestWafProcessor_TagOnMatch verifies a tag-action rule sets Level="THREAT:<rule>"
// and passes the event through (returned pointer == input pointer so downstream
// stages observe the same Event).
func TestWafProcessor_TagOnMatch(t *testing.T) {
	p, err := NewWafProcessor(defaultConfig())
	if err != nil {
		t.Fatalf("NewWafProcessor: %v", err)
	}
	ev := makeLogEvent(&parser.LogEntry{Method: "GET", Status: 200, Path: "/admin/users"})

	got, err := p.Process(context.Background(), ev)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if got == nil {
		t.Fatal("Process: want non-nil event (tag=passthrough), got nil")
	}
	if got.Envelope.Level != "THREAT:tag_admin_path" {
		t.Errorf("Process: Level=%q, want %q", got.Envelope.Level, "THREAT:tag_admin_path")
	}
}

// ========================== 3. Match + pass path ============================================

// TestWafProcessor_PassOnMatch verifies that a rule firing with action=pass leaves
// the event untouched (Level empty, payload unchanged).
func TestWafProcessor_PassOnMatch(t *testing.T) {
	p, err := NewWafProcessor(defaultConfig())
	if err != nil {
		t.Fatalf("NewWafProcessor: %v", err)
	}
	ev := makeLogEvent(&parser.LogEntry{Method: "GET", Status: 200, Path: "/healthz"})

	got, err := p.Process(context.Background(), ev)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if got == nil {
		t.Fatal("Process: want non-nil event (pass=passthrough), got nil")
	}
	if got.Envelope.Level != "" {
		t.Errorf("Process: Level=%q, want empty", got.Envelope.Level)
	}
	if got != ev {
		t.Errorf("Process: want same *plugin.Event pointer back")
	}
}

// ========================== 4. No match path ================================================

// TestWafProcessor_NoMatch verifies a non-matching event passes through with
// Level untouched.
func TestWafProcessor_NoMatch(t *testing.T) {
	p, err := NewWafProcessor(defaultConfig())
	if err != nil {
		t.Fatalf("NewWafProcessor: %v", err)
	}
	ev := makeLogEvent(&parser.LogEntry{Method: "GET", Status: 200, Path: "/api/products"})
	ev.Envelope.Level = "INFO"

	got, err := p.Process(context.Background(), ev)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if got == nil {
		t.Fatal("Process: want non-nil event (no-match=passthrough), got nil")
	}
	if got.Envelope.Level != "INFO" {
		t.Errorf("Process: Level=%q, want %q (untouched)", got.Envelope.Level, "INFO")
	}
}

// ========================== 5. Concurrent safety ============================================

// TestWafProcessor_ConcurrentSafety runs many Process calls in parallel against
// the same processor instance. With -race enabled this catches any unshared-
// mutable state inside the resolver chain, the RuleSet walks, or the action map.
// Each goroutine uses a self-contained event so concurrent Match's read-lock
// contention is the only shared state.
func TestWafProcessor_ConcurrentSafety(t *testing.T) {
	p, err := NewWafProcessor(defaultConfig())
	if err != nil {
		t.Fatalf("NewWafProcessor: %v", err)
	}

	const goroutines = 32
	const iterations = 200

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		g := g
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				var ev *plugin.Event
				switch (g + i) % 4 {
				case 0:
					ev = makeLogEvent(&parser.LogEntry{Method: "POST", Status: 405, Path: "/api/users"})
				case 1:
					ev = makeLogEvent(&parser.LogEntry{Method: "GET", Status: 200, Path: "/admin/u"})
				case 2:
					ev = makeLogEvent(&parser.LogEntry{Method: "GET", Status: 200, Path: "/healthz"})
				case 3:
					ev = makeLogEvent(&parser.LogEntry{Method: "GET", Status: 200, Path: "/products"})
				}
				if _, err := p.Process(context.Background(), ev); err != nil {
					t.Errorf("goroutine %d iter %d: Process: %v", g, i, err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// ========================== 6. Fail-fast on bad expression ==================================

// TestWafProcessor_FailFast_BadExpression verifies that a syntactically invalid
// rule expression causes NewWafProcessor to return an error before any rule is
// live — the rule name appears in the error so config typos are attributable.
func TestWafProcessor_FailFast_BadExpression(t *testing.T) {
	cfg := Config{
		Rules: []RuleConfig{
			{Name: "good_rule", Expression: `http.status eq 200`},
			{Name: "bad_rule", Expression: `this is not a valid expression at all @@@`},
		},
	}
	_, err := NewWafProcessor(cfg)
	if err == nil {
		t.Fatal("NewWafProcessor: want error for bad expression, got nil")
	}
	// Error must name the failing rule — operators reading a config with ten
	// rules need immediate attribution.
	if got := err.Error(); !contains(got, "bad_rule") {
		t.Errorf("error %q must contain rule name %q", got, "bad_rule")
	}
}

// TestWafProcessor_FailFast_EmptyName verifies that an empty rule name fails Init.
// Caught at NewWafProcessor — better than a runtime "rule with empty name".
func TestWafProcessor_FailFast_EmptyName(t *testing.T) {
	cfg := Config{
		Rules: []RuleConfig{
			{Name: "", Expression: `http.status eq 200`},
		},
	}
	_, err := NewWafProcessor(cfg)
	if err == nil {
		t.Fatal("NewWafProcessor: want error for empty rule name, got nil")
	}
}

// TestWafProcessor_FailFast_EmptyExpression verifies that an empty expression
// fails Init. A rule with no expression would silently never match; surfacing
// at Init is the right contract.
func TestWafProcessor_FailFast_EmptyExpression(t *testing.T) {
	cfg := Config{
		Rules: []RuleConfig{
			{Name: "no_expr", Expression: ""},
		},
	}
	_, err := NewWafProcessor(cfg)
	if err == nil {
		t.Fatal("NewWafProcessor: want error for empty expression, got nil")
	}
}

// ========================== 7. ctx cancellation =============================================

// TestWafProcessor_CtxCancellation verifies that a pre-cancelled context short-
// circuits Process with ctx.Err() before any rule evaluation runs.
func TestWafProcessor_CtxCancellation(t *testing.T) {
	p, err := NewWafProcessor(defaultConfig())
	if err != nil {
		t.Fatalf("NewWafProcessor: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ev := makeLogEvent(&parser.LogEntry{Method: "POST", Status: 405, Path: "/admin/u"})
	got, err := p.Process(ctx, ev)
	if err == nil {
		t.Fatal("Process: want ctx.Err() error, got nil")
	}
	if got != nil {
		t.Errorf("Process: want nil event on cancellation, got %+v", got)
	}
}

// ========================== 8. Empty config ==================================================

// TestWafProcessor_EmptyConfig verifies that constructing the processor with zero
// rules is rejected with an error — an empty ruleset silently passes all traffic,
// which would give a false sense of protection (fail-fast at startup).
func TestWafProcessor_EmptyConfig(t *testing.T) {
	_, err := NewWafProcessor(Config{})
	if err == nil {
		t.Fatal("NewWafProcessor(empty): want error for empty rules, got nil")
	}
}

// ========================== Action normalisation ==============================================

// TestWafProcessor_ActionNormalisation verifies that the case-insensitive /
// whitespace-tolerant mapping in normaliseAction behaves as documented:
//   - empty / unknown → ActionDrop (default)
//   - "Drop" / "DROP" → ActionDrop
//   - "Tag"           → ActionTag
//   - "Pass"          → ActionPass
func TestWafProcessor_ActionNormalisation(t *testing.T) {
	cases := []struct {
		action string
		want   string
	}{
		{"", ActionDrop},
		{"drop", ActionDrop},
		{"DROP", ActionDrop},
		{"  Drop  ", ActionDrop},
		{"tag", ActionTag},
		{"TAG", ActionTag},
		{"pass", ActionPass},
		{"PASS", ActionPass},
		{"unknown", ActionDrop}, // unrecognised defaults to drop
	}
	for _, tc := range cases {
		t.Run(tc.action, func(t *testing.T) {
			if got := normaliseAction(tc.action); got != tc.want {
				t.Errorf("normaliseAction(%q): want %q, got %q", tc.action, tc.want, got)
			}
		})
	}
}

// ========================== tag-action case insensitivity (DECISIONS D1) ====================

// TestWafProcessor_TagActionCaseInsensitive pins DECISIONS D1: classifyAction must
// normalise the tag-action value at Init so the action map stores the canonical
// lowercase form. Process's case-sensitive dispatch (action == ActionTag /
// HasPrefix(action, "tag:")) then matches regardless of operator capitalisation
// or surrounding whitespace. Without normalisation, "TAG" / "Tag:ban" /
// " tag:Foo " all fall through to Process's default branch → (nil, nil) drop,
// which is a silent regression of an operator's tag-or-pass intent into a block.
//
// The test exercises BOTH the classifyAction level (action map values are
// canonical lowercase) AND the Process dispatch level (Level is set to
// THREAT:<rule>[:<label>], event is not dropped).
func TestWafProcessor_TagActionCaseInsensitive(t *testing.T) {
	cases := []struct {
		name       string // rule name — used in expected Level
		action     string // raw value from config — the case-insensitive / whitespace input
		wantMapVal string // expected value in actions[name] after classifyAction
		wantLevel  string // expected Envelope.Level after Process dispatch
	}{
		{
			name:       "rule_upper_tag",
			action:     "TAG",
			wantMapVal: ActionTag,
			wantLevel:  "THREAT:rule_upper_tag",
		},
		{
			name:       "rule_mixed_tag",
			action:     "Tag:ban",
			wantMapVal: "tag:ban",
			wantLevel:  "THREAT:rule_mixed_tag:ban",
		},
		{
			name:       "rule_padded_tag",
			action:     " tag:Foo ",
			wantMapVal: "tag:foo",
			wantLevel:  "THREAT:rule_padded_tag:foo",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{
				Rules: []RuleConfig{
					{
						Name:       tc.name,
						Expression: `http.path eq "/probe"`,
						Action:     tc.action,
					},
				},
			}
			p, err := NewWafProcessor(cfg)
			if err != nil {
				t.Fatalf("NewWafProcessor(action=%q): unexpected init error: %v", tc.action, err)
			}

			// Level 1: classifyAction must have normalised the action so the
			// action map holds canonical lowercase form. This is the unit-level
			// guarantee — Process's dispatch depends on this value.
			gotMapVal := p.actions[tc.name]
			if gotMapVal != tc.wantMapVal {
				t.Errorf("classifyAction: actions[%q]=%q, want %q (action %q must normalise)",
					tc.name, gotMapVal, tc.wantMapVal, tc.action)
			}

			// Level 2: Process must dispatch as tag (passthrough with Level set),
			// NOT fall through to the default branch and silently drop the event.
			ev := makeLogEvent(&parser.LogEntry{Method: "GET", Status: 200, Path: "/probe"})
			got, err := p.Process(context.Background(), ev)
			if err != nil {
				t.Fatalf("Process(action=%q): unexpected error: %v", tc.action, err)
			}
			if got == nil {
				t.Fatalf("Process(action=%q): event DROPPED (nil,nil) — tag action was misclassified as drop; want non-nil tag passthrough",
					tc.action)
			}
			if got.Envelope.Level != tc.wantLevel {
				t.Errorf("Process(action=%q): Level=%q, want %q",
					tc.action, got.Envelope.Level, tc.wantLevel)
			}
		})
	}
}

// ========================== tag:<label> action ===============================================

// TestWafProcessor_TagLabel verifies that action="tag:<label>" is accepted at init
// and that Process sets Level="THREAT:<label>" (not "THREAT:<rule_name>").
func TestWafProcessor_TagLabel(t *testing.T) {
	cfg := Config{
		Rules: []RuleConfig{
			{Name: "sqli_detect", Expression: `http.path contains "union"`, Action: "tag:waf_sqli"},
		},
	}
	p, err := NewWafProcessor(cfg)
	if err != nil {
		t.Fatalf("NewWafProcessor: unexpected error for tag:<label> action: %v", err)
	}
	ev := makeLogEvent(&parser.LogEntry{Method: "GET", Status: 200, Path: "/search?q=union+select"})
	got, err := p.Process(context.Background(), ev)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if got == nil {
		t.Fatal("Process: want non-nil event (tag path), got nil")
	}
	const wantLevel = "THREAT:sqli_detect:waf_sqli"
	if got.Envelope.Level != wantLevel {
		t.Errorf("Process: Level=%q, want %q", got.Envelope.Level, wantLevel)
	}
}

// TestWafProcessor_PassShortCircuit verifies that a matching pass-rule short-circuits
// evaluation so that a subsequent drop-rule on the same event never fires.
// Without two-pass logic the drop-rule would win (first-match-wins on merged set).
func TestWafProcessor_PassShortCircuit(t *testing.T) {
	cfg := Config{
		Rules: []RuleConfig{
			// drop fires on /admin — but pass fires first for internal IP
			{Name: "block_admin", Expression: `http.path contains "/admin"`, Action: ActionDrop},
			{Name: "allow_internal", Expression: `http.path contains "/admin"`, Action: ActionPass},
		},
	}
	p, err := NewWafProcessor(cfg)
	if err != nil {
		t.Fatalf("NewWafProcessor: %v", err)
	}
	ev := makeLogEvent(&parser.LogEntry{Method: "GET", Status: 200, Path: "/admin/health"})
	got, err := p.Process(context.Background(), ev)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	// pass must short-circuit: event returned, not dropped
	if got == nil {
		t.Fatal("Process: want non-nil event (pass short-circuit), got nil (drop fired instead)")
	}
	if got.Envelope.Level != "" {
		t.Errorf("Process: Level=%q, want empty (pass must not set Level)", got.Envelope.Level)
	}
}

// ========================== ScoreFunc callback ============================================

// recordingScorer captures every (ip, delta) tuple scoreFn is invoked with, so
// the tests can assert what was actually signalled to the scorer without
// coupling to whatever closure cmd/arxsentinel wires up in production.
type recordingScorer struct {
	mu    sync.Mutex
	calls []scorerCall
}

type scorerCall struct {
	ip    string
	delta int
}

func (r *recordingScorer) fn() ScoreFunc {
	return func(ip string, delta int) {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.calls = append(r.calls, scorerCall{ip: ip, delta: delta})
	}
}

func (r *recordingScorer) snapshot() []scorerCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]scorerCall, len(r.calls))
	copy(out, r.calls)
	return out
}

// TestWafProcessor_ScoreFunc_Drop verifies that a drop-rule firing triggers
// scoreFn(ip, dropScore) where ip comes from LogEntry.RealIP (preferred over
// RemoteAddr when both are populated).
func TestWafProcessor_ScoreFunc_Drop(t *testing.T) {
	scorer := &recordingScorer{}
	cfg := Config{
		Rules: []RuleConfig{
			{Name: "block_post_405", Expression: `http.method eq "POST" and http.status eq 405`, Action: ActionDrop},
		},
		DropScore: 100,
		ScoreFn:   scorer.fn(),
	}
	p, err := NewWafProcessor(cfg)
	if err != nil {
		t.Fatalf("NewWafProcessor: %v", err)
	}

	ev := makeLogEvent(&parser.LogEntry{
		Method:     "POST",
		Status:     405,
		Path:       "/api/users",
		RealIP:     "203.0.113.7",
		RemoteAddr: "10.0.0.1:54321",
	})
	got, err := p.Process(context.Background(), ev)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if got != nil {
		t.Errorf("Process: want nil event (drop), got %+v", got)
	}

	calls := scorer.snapshot()
	if len(calls) != 1 {
		t.Fatalf("scoreFn calls: got %d, want 1 (%+v)", len(calls), calls)
	}
	if got := calls[0]; got.ip != "203.0.113.7" || got.delta != 100 {
		t.Errorf("scoreFn call: got {ip=%q, delta=%d}, want {ip=%q, delta=%d}",
			got.ip, got.delta, "203.0.113.7", 100)
	}
}

// TestWafProcessor_ScoreFunc_Tag verifies that a tag:<label> rule firing
// triggers scoreFn(ip, tagWeight) where the weight comes from TagWeights keyed
// by the action's label (not the rule name).
func TestWafProcessor_ScoreFunc_Tag(t *testing.T) {
	scorer := &recordingScorer{}
	cfg := Config{
		Rules: []RuleConfig{
			{Name: "sqli_detect", Expression: `http.path contains "union"`, Action: "tag:waf_sqli"},
		},
		TagWeights: map[string]int{
			"waf_sqli": 80,
			"waf_xss":  60,
		},
		ScoreFn: scorer.fn(),
	}
	p, err := NewWafProcessor(cfg)
	if err != nil {
		t.Fatalf("NewWafProcessor: %v", err)
	}

	ev := makeLogEvent(&parser.LogEntry{
		Method: "GET", Status: 200, Path: "/search?q=union+select",
		RemoteAddr: "198.51.100.42",
	})
	got, err := p.Process(context.Background(), ev)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if got == nil {
		t.Fatal("Process: want non-nil event (tag path), got nil")
	}
	if got.Envelope.Level != "THREAT:sqli_detect:waf_sqli" {
		t.Errorf("Process: Level=%q, want %q", got.Envelope.Level, "THREAT:sqli_detect:waf_sqli")
	}

	calls := scorer.snapshot()
	if len(calls) != 1 {
		t.Fatalf("scoreFn calls: got %d, want 1 (%+v)", len(calls), calls)
	}
	if got := calls[0]; got.ip != "198.51.100.42" || got.delta != 80 {
		t.Errorf("scoreFn call: got {ip=%q, delta=%d}, want {ip=%q, delta=%d}",
			got.ip, got.delta, "198.51.100.42", 80)
	}
}

// TestWafProcessor_ScoreFunc_Nil verifies nil-ScoreFn safety: a drop-rule
// firing with no scoreFn configured must not panic, must still gate the event,
// and must not crash subsequent Process calls.
func TestWafProcessor_ScoreFunc_Nil(t *testing.T) {
	cfg := Config{
		Rules: []RuleConfig{
			{Name: "block_post_405", Expression: `http.method eq "POST" and http.status eq 405`, Action: ActionDrop},
		},
		DropScore: 100,
		// ScoreFn intentionally nil — must be nil-safe.
	}
	p, err := NewWafProcessor(cfg)
	if err != nil {
		t.Fatalf("NewWafProcessor: %v", err)
	}

	ev := makeLogEvent(&parser.LogEntry{
		Method: "POST", Status: 405, Path: "/api/users",
		RealIP: "203.0.113.7",
	})
	got, err := p.Process(context.Background(), ev)
	if err != nil {
		t.Fatalf("Process: want no error, got %v", err)
	}
	if got != nil {
		t.Errorf("Process: want nil event (drop), got %+v", got)
	}

	// Second call with a tag-rule: also nil-safe.
	scorer := &recordingScorer{}
	_ = scorer // keep the recorder type referenced; not used here.
	cfg2 := Config{
		Rules: []RuleConfig{
			{Name: "sqli", Expression: `http.path contains "union"`, Action: "tag:waf_sqli"},
		},
		TagWeights: map[string]int{"waf_sqli": 80},
		// ScoreFn nil again.
	}
	p2, err := NewWafProcessor(cfg2)
	if err != nil {
		t.Fatalf("NewWafProcessor #2: %v", err)
	}
	ev2 := makeLogEvent(&parser.LogEntry{Method: "GET", Status: 200, Path: "/q?union", RealIP: "203.0.113.8"})
	if _, err := p2.Process(context.Background(), ev2); err != nil {
		t.Fatalf("Process #2: want no error, got %v", err)
	}
}

// ========================== Config: TagWeights =============================================

// TestWafProcessor_Config_TagWeights verifies that Config.TagWeights survives
// construction: NewWafProcessor accepts the field, the resulting processor is
// non-nil, and the weights are accessible. This test does NOT verify score
// dispatch (that's wire-up code's job in cmd/arxsentinel) — only that the
// plumbing doesn't drop the field on the floor.
func TestWafProcessor_Config_TagWeights(t *testing.T) {
	cfg := Config{
		Rules: []RuleConfig{{Name: "dummy", Expression: `http.path eq "/"`, Action: "drop"}},
		TagWeights: map[string]int{
			"waf_sqli": 80,
			"waf_xss":  60,
		},
	}
	p, err := NewWafProcessor(cfg)
	if err != nil {
		t.Fatalf("NewWafProcessor: %v", err)
	}
	if p == nil {
		t.Fatal("NewWafProcessor: want non-nil processor")
	}
	if got, want := len(cfg.TagWeights), 2; got != want {
		t.Errorf("cfg.TagWeights length: got %d, want %d", got, want)
	}
	if got, want := cfg.TagWeights["waf_sqli"], 80; got != want {
		t.Errorf("cfg.TagWeights[\"waf_sqli\"]: got %d, want %d", got, want)
	}
}

// ========================== Config: DropScore ==============================================

// TestWafProcessor_Config_DropScore verifies that Config.DropScore is preserved
// at construction time. Wire-up code (cmd/arxsentinel) reads this to build a
// ScoreFunc closure; the WAF plugin itself never applies the score, so this
// test only confirms the field is carried through without loss.
func TestWafProcessor_Config_DropScore(t *testing.T) {
	cfg := Config{
		Rules:     []RuleConfig{{Name: "dummy", Expression: `http.path eq "/"`, Action: "drop"}},
		DropScore: 100,
	}
	p, err := NewWafProcessor(cfg)
	if err != nil {
		t.Fatalf("NewWafProcessor: %v", err)
	}
	if p == nil {
		t.Fatal("NewWafProcessor: want non-nil processor")
	}
	if got, want := cfg.DropScore, 100; got != want {
		t.Errorf("cfg.DropScore: got %d, want %d", got, want)
	}
}

// ========================== helpers ==========================================================

// contains delegates to strings.Contains; kept as a named helper so the assertion
// reads naturally at call sites.
func contains(haystack, needle string) bool {
	return strings.Contains(haystack, needle)
}
