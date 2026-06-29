// ========================== pkg/processor/waf — Scheme / RuleSet wiring ===================
//   BuildScheme and NewRuleSetFromConfig are the rule-engine integration surface for the
//   WAF processor (Flow 001, Task H3). They sit between Manifest.Produces and a runtime
//   ruleset.RuleSet so WafProcessor can call Match(event, resolver) at line rate.
//
//   WHAT IS HERE:
//     - Config / RuleConfig — runtime configuration structs parsed by the factory.
//     - BuildScheme         — iterates Manifest.Produces and registers each typed field
//                              with the rule engine's Catalog (via builder.Builder).
//     - NewRuleSetFromConfig — fail-fast compile of every rule at Init time; returns
//                              a non-nil RuleSet + an action map (`name → "pass"|"drop"
//                              |"tag"`, defaulting to "drop") or a wrapped error
//                              naming the rule that failed to compile.
//
//   WHAT IS NOT HERE:
//     - Manifest / Resolver / Process — owned by sibling files in this package
//     - The Engine itself — pkg/rule/{compiler,parser,ruleset}
//
//   DEPENDENCY RULE:
//     pkg/processorplugins/waf → arx-core (pkg/plugin + pkg/rule/{builder,ruleset}) +
//     stdlib.
//
//   CONCURRENCY:
//     All exported helpers run at Init time (factory called once by the registry), so
//     no per-field locks are needed. The returned *ruleset.RuleSet is the thread-safe
//     type owned by arx-core (pkg/rule/ruleset); WafProcessor consults it from
//     per-event goroutines under RuleSet's read lock.

package waf

import (
	"fmt"
	"strings"

	"github.com/mr-addams/arx-core/pkg/plugin"
	"github.com/mr-addams/arx-core/pkg/rule"
	"github.com/mr-addams/arx-core/pkg/rule/builder"
	"github.com/mr-addams/arx-core/pkg/rule/ruleset"
)

// ========================== Config / RuleConfig =============================================

// Action identifiers. They live as untyped strings on RuleConfig so YAML/JSON config
// files remain readable; switch on the value in WafProcessor.Process.
const (
	ActionDrop = "drop" // (nil, nil) — gate the event out of the pipeline
	ActionTag  = "tag"  // event.Envelope.Level = "THREAT" — flag for downstream scoring
	ActionPass = "pass" // pass through unchanged — useful for logging/side-effects
)

// defaultAction is the action applied when RuleConfig.Action is empty. "drop" is the
// safe default for a WAF plugin: an unconfigured rule with an "alert"-only intent
// would otherwise pass traffic through silently. Choosing "drop" surfaces
// misconfigured rules as a noisy drop (visible in metrics) rather than silent pass.
const defaultAction = ActionDrop

// RuleConfig is a single WAF rule: name + expression + action. The expression is in
// the arx-core rule language (see arx-core/pkg/rule/REFERENCE.md); the action is the
// WAF-side interpretation of a Match verdict (DECISION D12: the engine returns the
// verdict, the plugin decides what to do with it).
type RuleConfig struct {
	Name       string `yaml:"name"`       // YAML: waf.rules[].name — unique rule name
	Expression string `yaml:"expression"` // YAML: waf.rules[].expression — rule DSL
	Action     string `yaml:"action"`     // YAML: waf.rules[].action — "pass"|"drop"|"tag", default "drop"
}

// Config is the WAF plugin's top-level runtime configuration. The factory
// (register.go) passes one instance into NewWafProcessor; tests construct one
// directly to exercise fail-fast compile paths.
type Config struct {
	Rules []RuleConfig `yaml:"rules"`
}

// ========================== BuildScheme =====================================================

// BuildScheme registers every typed field declared in manifest's Produces with a fresh
// rule.Catalog and returns the resulting frozen Scheme. The Scheme compiles only
// against the http namespace plus the implicit core namespace every Scheme has (per
// pkg/rule/ruleset.New).
//
// Naming convention: Manifest.Produces entries use bare names ("method", "path",
// "raw_uri") — the namespace ("http") is fixed by Manifest.PluginID and is therefore
// implicit in the BuildScheme contract. Both the Manifest and the Scheme must agree
// on "http" (BuildScheme asserts PluginID == "waf") so a future PluginID change
// cannot silently route the WAF plugin into a different namespace.
//
// DECISION D7 reserves the dot character for the namespace separator only; sub-path
// style names like "uri.path" are flattened to a single segment ("path", "raw_uri")
// in the Manifest so Catalog.Register accepts them. BuildScheme therefore sees only
// flat, single-segment names — there is no implicit dotted-name handling here.
//
// Implementation note: BuildScheme uses cat.Project directly rather than the builder
// package because the builder's primary deliverable is a RuleSet, not a standalone
// Scheme. Catalog.Register for `core` fields is duplicated from builder.New here for
// the same reason — duplication is the cost of NOT having a Scheme-only API in the
// engine. A future cleanup can lift this into a pkg/rule/project helper.
//
// BuildScheme is separate from NewRuleSetFromConfig because callers that only want
// to introspect the field surface (e.g. a config validator) do not need to compile
// rules. H4 invokes NewRuleSetFromConfig; the integration test in H5 may use
// BuildScheme directly.
func BuildScheme(manifest plugin.Manifest) (*rule.Scheme, error) {
	if manifest.PluginID != "waf" {
		// Defensive — BuildScheme is named after the WAF plugin's namespace.
		// A future PluginID change must be reflected here so the rule namespace
		// stays in lockstep with the Manifest identity.
		return nil, fmt.Errorf("waf: BuildScheme requires PluginID %q, got %q", "waf", manifest.PluginID)
	}

	cat := rule.NewCatalog()
	// core namespace is implicit in every Scheme (see pkg/rule/ruleset.New),
	// so register the envelope fields here to make the Scheme self-contained.
	for _, fn := range []struct{ name string; t rule.FieldType }{
		{"timestamp", rule.TypeTimestamp},
		{"stream", rule.TypeString},
		{"source", rule.TypeString},
		{"source_type", rule.TypeString},
		{"level", rule.TypeString},
	} {
		if err := cat.Register("core", fn.name, fn.t); err != nil {
			return nil, fmt.Errorf("waf: register core.%s: %w", fn.name, err)
		}
	}
	// http namespace — every typed field from Manifest.Produces.
	for _, fd := range manifest.Produces {
		if err := cat.Register("http", fd.Name, fd.Type); err != nil {
			return nil, fmt.Errorf("waf: register http.%s: %w", fd.Name, err)
		}
	}
	return cat.Project("http", "core"), nil
}

// ========================== NewRuleSetFromConfig ===========================================

// NewRuleSetFromConfig builds a RuleSet from a parsed Config, compiling every rule
// expression against the Scheme built from the WAF Manifest. Compile failures fail
// fast (returning a wrapped error that names both the rule and the parser/compiler
// stage) — see DECISION D13: a misconfigured rule never poisons an otherwise-good
// RuleSet, but it MUST be visible at Init, not at the first Match.
//
// Returns:
//   - *ruleset.RuleSet — populated, ready for Match. Nil only on error.
//   - map[string]string — action map keyed by rule name. Empty (not nil) when no rules.
//     A key is present for every rule in cfg.Rules; Action normalised to one of
//     ActionDrop / ActionTag / ActionPass (unknown values fall back to ActionDrop).
//   - error — non-nil iff compilation failed; nil otherwise.
//
// Callers that want to expose live rule management can ignore the action map and
// instead use rs.Add / rs.Replace (ruleset.RuleSet is mutable, D13).
func NewRuleSetFromConfig(cfg Config, manifest plugin.Manifest) (*ruleset.RuleSet, map[string]string, error) {
	// Step 1: build the Scheme-bearing RuleSet via builder. Going through
	// builder rather than BuildScheme + manual ruleset.NewWithCompiler keeps
	// the registration logic in one place; BuildScheme is still exposed for
	// introspection callers that don't need rules compiled.
	b := builder.New("http")
	for _, fd := range manifest.Produces {
		b.Field("http", fd.Name, fd.Type)
	}
	if err := b.Err(); err != nil {
		return nil, nil, fmt.Errorf("waf: register fields: %w", err)
	}
	rs, err := b.Ruleset()
	if err != nil {
		// Bubble the builder's error (duplicate field, unknown FieldType, ...)
		// unchanged — the caller already has the diagnostic surface it needs.
		return nil, nil, fmt.Errorf("waf: build ruleset: %w", err)
	}

	// Step 2: compile each rule. Add returns the wrapped parser/compiler error
	// with the stage tagged ("parse error: ..." / "compile error: ...") — we
	// additionally prefix with the rule name so a config with ten rules makes
	// the failure immediately attributable.
	actions := make(map[string]string, len(cfg.Rules))
	for i, ruleCfg := range cfg.Rules {
		if ruleCfg.Name == "" {
			return nil, nil, fmt.Errorf("waf: rule #%d has empty name", i+1)
		}
		if ruleCfg.Expression == "" {
			return nil, nil, fmt.Errorf("waf: rule %q has empty expression", ruleCfg.Name)
		}
		if err := rs.Add(ruleCfg.Name, ruleCfg.Expression); err != nil {
			return nil, nil, fmt.Errorf("waf: rule %q: %w", ruleCfg.Name, err)
		}
		actions[ruleCfg.Name] = normaliseAction(ruleCfg.Action)
	}

	return rs, actions, nil
}

// ========================== internal helpers ===============================================

// normaliseAction maps the user-supplied Action string to one of ActionDrop /
// ActionTag / ActionPass. Unknown or empty values fall back to ActionDrop (the
// safe default — see defaultAction). The map is intentionally case-insensitive
// because YAML config is editor-friendly but inconsistent.
func normaliseAction(a string) string {
	switch strings.ToLower(strings.TrimSpace(a)) {
	case ActionPass:
		return ActionPass
	case ActionTag:
		return ActionTag
	case "", ActionDrop:
		return ActionDrop
	default:
		// Unknown action: the operator will surface this as a misconfigured
		// rule that doesn't fire as expected. Normalise to drop — the
		// safest fallback for a WAF gate.
		return ActionDrop
	}
}
