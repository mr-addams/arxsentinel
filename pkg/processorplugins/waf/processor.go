// ========================== pkg/processor/waf — Processor =================================
//   WafProcessor evaluates a pre-compiled rule set against the http.* fields of each
//   pipeline event and routes the verdict through a per-rule action policy (drop / tag /
//   pass). The plugin is the canonical Flow 001 example of "engine returns predicate,
//   plugin decides action" (DECISION D12).
//
//   WHAT IS HERE:
//     - WafProcessor       — plugin.Processor implementation owning the RuleSet and
//                            resolver pair.
//     - NewWafProcessor    — constructor: compiles cfg.Rules at Init time
//                            (fail-fast on bad expression), stores the action map.
//     - Name / Manifest    — plugin identity surface.
//     - Process            — ctx-respecting → RuleSet.Match → action dispatch
//                            (drop → (nil, nil), tag → set Level="THREAT", pass →
//                            pass-through).
//
//   WHAT IS NOT HERE:
//     - Manifest var      — manifest.go
//     - HttpResolver      — resolver.go
//     - Registration      — register.go
//     - Scheme / RuleSet  — ruleset.go

package waf

import (
	"context"
	"fmt"

	"github.com/mr-addams/arx-core/pkg/plugin"
	"github.com/mr-addams/arx-core/pkg/rule"
	"github.com/mr-addams/arx-core/pkg/rule/ruleset"
)

// ========================== WafProcessor ===================================================

// chainedResolver implements rule.FieldResolver by trying a list of underlying
// resolvers in order and returning the first hit. It is the dispatch chain the brief
// references: "chain of EnvelopeResolver + HttpResolver" — both stateless, both
// share-by-value, both supplied through this constructor.
//
// The chain's order (EnvelopeResolver first, then HttpResolver) is intentional:
// envelope fields are Core-owned and queried on every rule path, while the http
// namespace is plugin-owned. Keeping envelope first avoids paying the CutPrefix
// cost on http.* fields just to reject them.
type chainedResolver struct {
	resolvers []rule.FieldResolver
}

// Compile-time assertion: chainedResolver satisfies the FieldResolver interface.
var _ rule.FieldResolver = (*chainedResolver)(nil)

func (c *chainedResolver) Resolve(field string, event *plugin.Event) (rule.Value, bool) {
	for _, r := range c.resolvers {
		if v, ok := r.Resolve(field, event); ok {
			return v, true
		}
	}
	return rule.Value{}, false
}

// newChainedResolver builds a dispatch chain covering core.* + http.* namespaces.
// Both resolvers are stateless so this can be called once at Init and reused for
// every Process call.
func newChainedResolver() *chainedResolver {
	return &chainedResolver{
		resolvers: []rule.FieldResolver{
			rule.EnvelopeResolver{},
			HttpResolver{},
		},
	}
}

// WafProcessor applies a compiled WAF rule set to incoming events.
//
// Concurrency: the processor holds references to the RuleSet (which is internally
// RWMutex-protected, DECISION D13) and to a stateless resolver chain. Process is
// safe to call from multiple goroutines.
type WafProcessor struct {
	rules    *ruleset.RuleSet
	actions  map[string]string
	resolver *chainedResolver
}

// Ensure WafProcessor satisfies plugin.Processor at compile time.
var _ plugin.Processor = (*WafProcessor)(nil)

// NewWafProcessor compiles cfg.Rules at Init time. A bad expression returns
// (nil, error) with the rule name and parser/compiler stage in the message
// (fail-fast — never silently skips a misconfigured rule).
func NewWafProcessor(cfg Config) (*WafProcessor, error) {
	if cfg.Rules == nil {
		// Empty config is legal (plugin passes through every event) — but
		// using a typed empty slice keeps actions map non-nil for caller
		// simplicity.
		cfg.Rules = []RuleConfig{}
	}

	rs, actions, err := NewRuleSetFromConfig(cfg, Manifest)
	if err != nil {
		return nil, fmt.Errorf("waf: %w", err)
	}

	return &WafProcessor{
		rules:    rs,
		actions:  actions,
		resolver: newChainedResolver(),
	}, nil
}

// Name returns "waf".
func (p *WafProcessor) Name() string { return "waf" }

// Manifest returns the plugin manifest.
func (p *WafProcessor) Manifest() plugin.Manifest { return Manifest }

// ========================== Process ============================================================

// Process evaluates every compiled rule against event + resolver chain and applies
// the matched rule's action. The first matching rule wins — subsequent rules are
// not evaluated (DECISION D12: first-match-wins is the natural RuleSet semantics).
//
// Action dispatch (DECISION D12 — engine returns verdict, plugin decides):
//
//	"drop" → return (nil, nil)            — gate the event out of the pipeline
//	"tag"  → Level="THREAT"; return event — flag for downstream scoring / sinks
//	"pass" → return event                 — pass through unchanged
//
// The "tag" case is the architect-verdict compromise for Flow 001: plugin.Event has
// no convention for "matched rule name" and Envelope is fixed-shape. Level is the
// only writable signal downstream stages read; piggybacking the matched rule's
// name there ("THREAT:rule_name") is a self-documenting extension that downstream
// sinks (which already parse Level) can split on ":" if they care to.
//
// Returns:
//
//	(event,    nil) — passthrough (no rule fired, or action="pass"/"tag")
//	(nil,      nil) — drop path (rule fired with action="drop")
//	(nil,   ctx.Err()) — cancellation honored before any rule evaluation
func (p *WafProcessor) Process(ctx context.Context, event *plugin.Event) (*plugin.Event, error) {
	// ── Respect cancellation ──────────────────────────────────────────────────────────
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// ── Evaluate the rule chain ───────────────────────────────────────────────────────
	name, matched := p.rules.Match(event, p.resolver)
	if !matched {
		return event, nil
	}

	// ── Apply the matched rule's action ───────────────────────────────────────────────
	switch p.actions[name] {
	case ActionDrop:
		return nil, nil
	case ActionTag:
		event.Envelope.Level = "THREAT:" + name
		return event, nil
	case ActionPass:
		// Passthrough.
		return event, nil
	default:
		// Unknown action value — fail-closed (drop) rather than fail-open
		// (silent passthrough). For a WAF gate the safer outcome is to gate
		// the event out.
		return nil, nil
	}
}
