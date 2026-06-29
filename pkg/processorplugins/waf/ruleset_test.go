// ========================== pkg/processor/waf — ruleset tests ===========================
//   Coverage for BuildScheme and NewRuleSetFromConfig (Flow 001, Task H3).
//
//   Test surfaces:
//     1. BuildScheme on a valid WAF Manifest produces a Scheme containing every
//        http.* field from Manifest.Produces.
//     2. BuildScheme on a wrong PluginID returns an error.
//     3. NewRuleSetFromConfig compiles a happy-path config and returns a non-nil
//        RuleSet with the action map populated.
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

// TestNewRuleSetFromConfig_OK verifies that a well-formed config compiles and the
// action map carries every rule (with normalised action values).
func TestNewRuleSetFromConfig_OK(t *testing.T) {
	cfg := Config{
		Rules: []RuleConfig{
			{Name: "r1", Expression: `http.status eq 200`, Action: ActionDrop},
			{Name: "r2", Expression: `http.method eq "GET"`, Action: ActionTag},
			{Name: "r3", Expression: `http.path eq "/x"`, Action: ActionPass},
			{Name: "r4", Expression: `http.path eq "/y"`}, // no action → default drop
		},
	}
	rs, actions, err := NewRuleSetFromConfig(cfg, Manifest)
	if err != nil {
		t.Fatalf("NewRuleSetFromConfig: %v", err)
	}
	if rs == nil {
		t.Fatal("NewRuleSetFromConfig: want non-nil RuleSet")
	}
	if len(actions) != 4 {
		t.Fatalf("actions: want 4 entries, got %d (%v)", len(actions), actions)
	}
	if actions["r1"] != ActionDrop {
		t.Errorf("actions[r1]=%q, want %q", actions["r1"], ActionDrop)
	}
	if actions["r2"] != ActionTag {
		t.Errorf("actions[r2]=%q, want %q", actions["r2"], ActionTag)
	}
	if actions["r3"] != ActionPass {
		t.Errorf("actions[r3]=%q, want %q", actions["r3"], ActionPass)
	}
	if actions["r4"] != ActionDrop {
		t.Errorf("actions[r4]=%q, want %q (default drop)", actions["r4"], ActionDrop)
	}
	// rs should also expose the four rules via Rules() (the introspection API).
	if got := rs.Rules(); len(got) != 4 {
		t.Errorf("Rules(): want 4 rules, got %d", len(got))
	}
}

// ========================== 4. NewRuleSetFromConfig fail-fast ================================

// TestNewRuleSetFromConfig_BadExpression verifies that a single bad expression in
// the config fails the whole Init — atomicity (D13). The error message must name
// the offending rule.
func TestNewRuleSetFromConfig_BadExpression(t *testing.T) {
	cfg := Config{
		Rules: []RuleConfig{
			{Name: "good", Expression: `http.status eq 200`},
			{Name: "broken", Expression: `((( invalid syntax`},
		},
	}
	rs, _, err := NewRuleSetFromConfig(cfg, Manifest)
	if err == nil {
		t.Fatal("NewRuleSetFromConfig: want error for bad expression")
	}
	if rs != nil {
		t.Errorf("NewRuleSetFromConfig: want nil RuleSet on error, got %v", rs)
	}
	if msg := err.Error(); !contains(msg, "broken") {
		t.Errorf("error %q must name the failing rule %q", msg, "broken")
	}
}

// contains is defined in processor_test.go (same package — both test files share
// the waf package and the helper is small enough to live in one place).
