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
//                              TWO compiled RuleSets (passRS — action="pass" whitelist
//                              rules, gateRS — action="drop"/"tag:..." threat rules) +
//                              an action map for gateRS only. Returns a wrapped error
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

// NewRuleSetFromConfig builds TWO RuleSets from a parsed Config, compiling every rule
// expression against the Scheme built from the WAF Manifest. Compile failures fail
// fast (returning a wrapped error that names both the rule and the parser/compiler
// stage) — see DECISION D13: a misconfigured rule never poisons an otherwise-good
// RuleSet, but it MUST be visible at Init, not at the first Match.
//
// Two-pass design (Task H8): the rule set is split by action prefix at Init time so
// WafProcessor can do whitelist-first / threat-second at line rate:
//
//   - passRS — rules with action="pass". WafProcessor runs passRS.Match FIRST and
//     short-circuits on a hit (whitelisted event skips the threat check).
//   - gateRS — rules with action="drop" or action starting with "tag:". The threat
//     check; matched rule's action is dispatched via the `actions` map.
//   - anything else (empty Action is normalised to "drop", unknown values return
//     an error here rather than silently fall back — see classifyAction).
//
// Why two RuleSets instead of one with per-rule action tags: a single RuleSet.Match
// returns the first hit regardless of action priority. To implement whitelist-first
// semantics we MUST evaluate pass-rules before gate-rules, which means they cannot
// share a single RuleSet — Match() does not accept an "action filter" parameter.
// Each RuleSet is a self-contained engine over the same Scheme, so the cost is just
// one extra catalog/scheme/compiler trio at Init (one-time cost).
//
// Returns:
//   - *ruleset.RuleSet (passRS) — whitelist rules, ready for Match. Non-nil even when
//     empty (Rules() returns an empty slice); the caller's "has pass rules" check
//     uses len(rs.Rules()) > 0.
//   - *ruleset.RuleSet (gateRS) — threat rules (drop + tag:*), ready for Match.
//     Non-nil even when empty (same as passRS).
//   - map[string]string — action map keyed by rule name, contains ONLY gateRS rules.
//     A key is present for every rule routed to gateRS; Action normalised to one of
//     ActionDrop / ActionTag:... (unknown actions cause an error before this point).
//     Pass-rules do NOT appear in this map — WafProcessor short-circuits on passRS
//     hit and never consults the action map for them.
//   - error — non-nil iff compilation failed OR an unknown action was found; nil
//     otherwise. The returned RuleSets are nil on error (atomic init, D13).
//
// Callers that want to expose live rule management can ignore the action map and
// instead use passRS.Add / gateRS.Add (ruleset.RuleSet is mutable, D13) — keeping
// the two RuleSets in sync with their action categories is the caller's job.
func NewRuleSetFromConfig(cfg Config, manifest plugin.Manifest) (passRS, gateRS *ruleset.RuleSet, actions map[string]string, err error) {
	// ── Step 1: validate config and classify each rule by action ─────────────────────
	// classifyAction performs both classification (which RuleSet the rule belongs to)
	// and validation (unknown action is an error). The empty-action default lives in
	// classifyAction so the case-insensitive normalisation is applied in one place.
	// Two buckets: passNames and gateNames hold rule names by destination; we
	// collect expressions in cfg.Rules order so a misconfigured rule produces a
	// deterministic error (first failing rule name in the message).
	passEntries := make([]compileJob, 0)
	gateEntries := make([]compileJob, 0)
	passNames := make([]string, 0)
	gateNames := make([]string, 0)
	actions = make(map[string]string, len(cfg.Rules))

	for i, ruleCfg := range cfg.Rules {
		if ruleCfg.Name == "" {
			return nil, nil, nil, fmt.Errorf("waf: rule #%d has empty name", i+1)
		}
		if ruleCfg.Expression == "" {
			return nil, nil, nil, fmt.Errorf("waf: rule %q has empty expression", ruleCfg.Name)
		}
		bucket, normalisedAction, err := classifyAction(ruleCfg.Name, ruleCfg.Action)
		if err != nil {
			return nil, nil, nil, err
		}
		switch bucket {
		case actionBucketPass:
			passEntries = append(passEntries, compileJob{expr: ruleCfg.Expression})
			passNames = append(passNames, ruleCfg.Name)
		case actionBucketGate:
			gateEntries = append(gateEntries, compileJob{expr: ruleCfg.Expression})
			gateNames = append(gateNames, ruleCfg.Name)
			actions[ruleCfg.Name] = normalisedAction
		}
	}

	// ── Step 2: build passRS ─────────────────────────────────────────────────────────
	passRS, err = buildRuleSet("pass", manifest, passNames, passEntries)
	if err != nil {
		return nil, nil, nil, err
	}

	// ── Step 3: build gateRS ─────────────────────────────────────────────────────────
	gateRS, err = buildRuleSet("gate", manifest, gateNames, gateEntries)
	if err != nil {
		return nil, nil, nil, err
	}

	return passRS, gateRS, actions, nil
}

// compileJob carries one rule's expression through the build pipeline. The
// paired names slice is kept separate so the order of cfg.Rules is preserved
// at Add-time (and so error messages can name the rule, not an index).
type compileJob struct {
	expr string
}

// buildRuleSet constructs a single RuleSet via builder.New and adds the given rules
// in order. On any error, returns nil + the wrapped error (caller maps to atomic
// init failure). The "label" argument is used in error messages only — "pass" or
// "gate" — so the diagnostic names the bucket.
func buildRuleSet(label string, manifest plugin.Manifest, names []string, entries []compileJob) (*ruleset.RuleSet, error) {
	b := builder.New("http")
	for _, fd := range manifest.Produces {
		b.Field("http", fd.Name, fd.Type)
	}
	if err := b.Err(); err != nil {
		return nil, fmt.Errorf("waf: register fields (%s): %w", label, err)
	}
	rs, err := b.Ruleset()
	if err != nil {
		return nil, fmt.Errorf("waf: build ruleset (%s): %w", label, err)
	}
	for i, entry := range entries {
		if err := rs.Add(names[i], entry.expr); err != nil {
			return nil, fmt.Errorf("waf: rule %q: %w", names[i], err)
		}
	}
	return rs, nil
}

// ========================== internal helpers ===============================================

// actionBucket is the destination RuleSet for a rule, decided by its action string
// at Init time. NewRuleSetFromConfig uses this to split cfg.Rules into the passRS
// and gateRS RuleSets without re-parsing the action at Match time.
type actionBucket int

const (
	actionBucketPass actionBucket = iota // action="pass" — whitelist, short-circuits
	actionBucketGate                     // action="drop" or "tag[:suffix]" — threat check
)

// classifyAction decides which RuleSet a rule belongs to AND normalises the action
// value for the gateRS action map. Returns an error for unknown actions so a
// misconfigured rule is visible at Init (fail-fast, D13), not at the first Match.
//
// Rules:
//
//   - empty action        → gate bucket, normalised = ActionDrop (the default — see
//                            defaultAction). An unconfigured rule falls through to
//                            the safe WAF behaviour: gate the event out.
//   - "pass" (any case)   → pass bucket, normalised = ActionPass. The rule never
//                            appears in the action map (passRS short-circuits before
//                            WafProcessor consults the map).
//   - "drop" (any case)   → gate bucket, normalised = ActionDrop.
//   - "tag" (any case)    → gate bucket, normalised = ActionTag.
//   - "tag:<suffix>"      → gate bucket, normalised = original action. The suffix
//                            is preserved so downstream consumers (e.g. metrics
//                            tags, executor routing) can read the rule's intent
//                            without losing information.
//   - anything else       → error: an unknown action would otherwise silently fall
//                            through the gate and re-introduce the silent-pass bug
//                            that D12 was designed to prevent.
func classifyAction(ruleName, action string) (actionBucket, string, error) {
	normalised := strings.ToLower(strings.TrimSpace(action))
	switch {
	case normalised == "":
		return actionBucketGate, ActionDrop, nil
	case normalised == ActionPass:
		return actionBucketPass, ActionPass, nil
	case normalised == ActionDrop:
		return actionBucketGate, ActionDrop, nil
	case normalised == ActionTag, strings.HasPrefix(normalised, "tag:"):
		// Preserve the original (case-preserved) action for the action map so
		// "tag:foo" survives as "tag:foo", not "tag:foo".toLowerCase(). The
		// match is case-insensitive but the stored value keeps user intent.
		return actionBucketGate, action, nil
	default:
		return 0, "", fmt.Errorf("waf: unknown action %q for rule %q", action, ruleName)
	}
}

// normaliseAction maps the user-supplied Action string to one of ActionDrop /
// ActionTag / ActionPass. Unknown or empty values fall back to ActionDrop (the
// safe default — see defaultAction). The map is intentionally case-insensitive
// because YAML config is editor-friendly but inconsistent.
//
// RETAINED for TestWafProcessor_ActionNormalisation — that test pins the
// case-insensitive / whitespace-tolerant mapping as a separate contract from
// classifyAction. NewRuleSetFromConfig itself uses classifyAction; the public
// ActionNormalisation contract is preserved for any external callers that
// depended on the lenient mapping.
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
