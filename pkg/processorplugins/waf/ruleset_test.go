// ========================== pkg/processor/waf — ruleset tests ===========================
//   Coverage for BuildScheme and NewRuleSetFromConfig (Flow 001, Task H3 + H8).
//
//   Test surfaces:
//     1. BuildScheme on a valid WAF Manifest produces a Scheme containing every
//        http.* field from Manifest.Produces.
//     2. BuildScheme on a wrong PluginID returns an error.
//     3. NewRuleSetFromConfig compiles a happy-path config into two RuleSets
//        (passRS + gateRS) and an action map containing ONLY gateRS rules
//        (Task H8 — two-pass design).
//     4. NewRuleSetFromConfig fails fast on a syntactically invalid expression.

package waf

import (
	"testing"

	"github.com/mr-addams/arx-core/pkg/plugin"
)

// ========================== 1. BuildScheme happy path ======================================

// TestBuildScheme_OK verifies that BuildScheme on the canonical WAF Manifest yields
// a Scheme whose Field surface contains every FieldDecl.Name from Manifest.Produces.
func TestBuildScheme_OK(t *testing.T) {
	scheme, err := BuildScheme(Manifest)
	if err != nil {
		t.Fatalf("BuildScheme: %v", err)
	}
	if scheme == nil {
		t.Fatal("BuildScheme: want non-nil Scheme")
	}

	// Every Manifest.Produces field must appear in the Scheme as http.<name>.
	want := make(map[string]bool, len(Manifest.Produces))
	for _, fd := range Manifest.Produces {
		want["http."+fd.Name] = true
	}

	for _, fi := range scheme.Fields() {
		delete(want, fi.FullName())
	}
	if len(want) > 0 {
		missing := make([]string, 0, len(want))
		for k := range want {
			missing = append(missing, k)
		}
		t.Errorf("Scheme missing fields: %v", missing)
	}
}

// ========================== 2. BuildScheme wrong PluginID ====================================

// TestBuildScheme_RejectsForeignManifest verifies the PluginID guard. The Scheme
// namespace ("http") is owned by this plugin — a foreign Manifest must not silently
// route its fields through WafProcessor.
func TestBuildScheme_RejectsForeignManifest(t *testing.T) {
	foreign := plugin.Manifest{
		PluginID:  "not_waf",
		Role:      plugin.RoleProcessor,
		InputType: plugin.TypeStructured,
		Produces:  Manifest.Produces,
	}
	_, err := BuildScheme(foreign)
	if err == nil {
		t.Fatal("BuildScheme: want error for foreign PluginID, got nil")
	}
}

// ========================== 3. NewRuleSetFromConfig happy path ==============================

// TestNewRuleSetFromConfig_OK verifies that a well-formed config compiles into two
// RuleSets (passRS for pass-rules, gateRS for drop/tag) and the action map carries
// only the gateRS rules (with normalised action values).
func TestNewRuleSetFromConfig_OK(t *testing.T) {
	cfg := Config{
		Rules: []RuleConfig{
			{Name: "r1", Expression: `http.status eq 200`, Action: ActionDrop},  // gate
			{Name: "r2", Expression: `http.method eq "GET"`, Action: ActionTag}, // gate
			{Name: "r3", Expression: `http.path eq "/x"`, Action: ActionPass},   // pass
			{Name: "r4", Expression: `http.path eq "/y"`},                       // gate, default drop
		},
	}
	passRS, gateRS, actions, err := NewRuleSetFromConfig(cfg, Manifest)
	if err != nil {
		t.Fatalf("NewRuleSetFromConfig: %v", err)
	}
	if passRS == nil {
		t.Fatal("NewRuleSetFromConfig: want non-nil passRS")
	}
	if gateRS == nil {
		t.Fatal("NewRuleSetFromConfig: want non-nil gateRS")
	}
	// actions map covers gateRS rules ONLY (r1, r2, r4) — pass-rules (r3) never
	// reach the action dispatch path because WafProcessor short-circuits on them.
	if len(actions) != 3 {
		t.Fatalf("actions: want 3 entries (gate-only), got %d (%v)", len(actions), actions)
	}
	if actions["r1"] != ActionDrop {
		t.Errorf("actions[r1]=%q, want %q", actions["r1"], ActionDrop)
	}
	if actions["r2"] != ActionTag {
		t.Errorf("actions[r2]=%q, want %q", actions["r2"], ActionTag)
	}
	if actions["r4"] != ActionDrop {
		t.Errorf("actions[r4]=%q, want %q (default drop)", actions["r4"], ActionDrop)
	}
	if _, present := actions["r3"]; present {
		t.Errorf("actions must NOT contain pass-rule r3, got %q", actions["r3"])
	}
	// gateRS exposes the three gate rules via Rules() (the introspection API).
	if got := gateRS.Rules(); len(got) != 3 {
		t.Errorf("gateRS.Rules(): want 3 rules, got %d", len(got))
	}
	// passRS exposes the one pass rule via Rules().
	if got := passRS.Rules(); len(got) != 1 {
		t.Errorf("passRS.Rules(): want 1 rule, got %d", len(got))
	}
}

// ========================== 4. NewRuleSetFromConfig fail-fast ================================

// TestNewRuleSetFromConfig_BadExpression verifies that a single bad expression in
// the config fails the whole Init — atomicity (D13). The error message must name
// the offending rule. On error both RuleSets must be nil so the caller cannot
// accidentally use a partially-initialised processor.
func TestNewRuleSetFromConfig_BadExpression(t *testing.T) {
	cfg := Config{
		Rules: []RuleConfig{
			{Name: "good", Expression: `http.status eq 200`},
			{Name: "broken", Expression: `((( invalid syntax`},
		},
	}
	passRS, gateRS, _, err := NewRuleSetFromConfig(cfg, Manifest)
	if err == nil {
		t.Fatal("NewRuleSetFromConfig: want error for bad expression")
	}
	if passRS != nil {
		t.Errorf("NewRuleSetFromConfig: want nil passRS on error, got %v", passRS)
	}
	if gateRS != nil {
		t.Errorf("NewRuleSetFromConfig: want nil gateRS on error, got %v", gateRS)
	}
	if msg := err.Error(); !contains(msg, "broken") {
		t.Errorf("error %q must name the failing rule %q", msg, "broken")
	}
}

// contains is defined in processor_test.go (same package — both test files share
// the waf package and the helper is small enough to live in one place).
