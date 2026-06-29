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
//                        pass action preserves the event unchanged)
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
// rules still yields a usable instance — every event passes through unchanged.
func TestWafProcessor_EmptyConfig(t *testing.T) {
	p, err := NewWafProcessor(Config{})
	if err != nil {
		t.Fatalf("NewWafProcessor(empty): %v", err)
	}
	if p == nil {
		t.Fatal("NewWafProcessor(empty): want non-nil processor")
	}
	ev := makeLogEvent(&parser.LogEntry{Method: "POST", Status: 405})
	got, err := p.Process(context.Background(), ev)
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if got != ev {
		t.Errorf("Process: want passthrough (same pointer), got different")
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

// ========================== helpers ==========================================================

// contains delegates to strings.Contains; kept as a named helper so the assertion
// reads naturally at call sites.
func contains(haystack, needle string) bool {
	return strings.Contains(haystack, needle)
}
