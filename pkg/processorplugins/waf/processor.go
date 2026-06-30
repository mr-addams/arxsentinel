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
	"strings"

	"github.com/mr-addams/arx-core/pkg/parser"
	"github.com/mr-addams/arx-core/pkg/plugin"
	"github.com/mr-addams/arx-core/pkg/rule"
	"github.com/mr-addams/arx-core/pkg/rule/ruleset"
)

// ScoreFunc is called after a rule fires to signal a score delta to the scorer.
// ip is the client IP string. delta is the score to add.
// Nil-safe: if ScoreFunc is nil, no score signal is sent.
type ScoreFunc func(ip string, delta int)

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
// Two-pass design (Task H8): the rule set is split at Init time into a whitelist
// (passRules) and a threat set (gateRules). At Process time, passRules is evaluated
// FIRST; a hit short-circuits the threat check (whitelisted event is passed through
// unchanged). Only when no pass-rule matches does the processor fall through to
// gateRules and apply the matched rule's action (drop / tag[:suffix]).
//
// Concurrency: the processor holds references to two RuleSets (each internally
// RWMutex-protected, DECISION D13) and to a stateless resolver chain. Process is
// safe to call from multiple goroutines — passRules and gateRules never share a
// lock, so the two Match calls can run concurrently if a future caller wants to
// parallelise them. Today they run sequentially because the second Match only
// happens on a passRules miss (so it's not on the production-hot path).
type WafProcessor struct {
	passRules  *ruleset.RuleSet
	gateRules  *ruleset.RuleSet
	actions    map[string]string
	resolver   *chainedResolver
	scoreFn    ScoreFunc
	dropScore  int
	tagWeights map[string]int
}

// Ensure WafProcessor satisfies plugin.Processor at compile time.
var _ plugin.Processor = (*WafProcessor)(nil)

// NewWafProcessor compiles cfg.Rules at Init time. A bad expression returns
// (nil, error) with the rule name and parser/compiler stage in the message
// (fail-fast — never silently skips a misconfigured rule).
func NewWafProcessor(cfg Config) (*WafProcessor, error) {
	if len(cfg.Rules) == 0 {
		// Empty rules list is a configuration error, not a legal state: a WAF
		// with no rules passes every event through and creates a false sense
		// of protection. Fail-fast surfaces a deployment typo before the
		// instance accepts traffic.
		return nil, fmt.Errorf("waf: rules list is empty — WAF plugin requires at least one rule")
	}

	passRS, gateRS, actions, err := NewRuleSetFromConfig(cfg, Manifest)
	if err != nil {
		return nil, fmt.Errorf("waf: %w", err)
	}

	return &WafProcessor{
		passRules:  passRS,
		gateRules:  gateRS,
		actions:    actions,
		resolver:   newChainedResolver(),
		scoreFn:    cfg.ScoreFn,
		dropScore:  cfg.DropScore,
		tagWeights: cfg.TagWeights,
	}, nil
}

// Name returns "waf".
func (p *WafProcessor) Name() string { return "waf" }

// Manifest returns the plugin manifest.
func (p *WafProcessor) Manifest() plugin.Manifest { return Manifest }

// clientIP extracts the client IP from the event payload.
// Returns empty string for non-LogEntry payloads (score signal skipped).
func clientIP(event *plugin.Event) string {
	le, ok := event.Payload.(*parser.LogEntry)
	if !ok || le == nil {
		return ""
	}
	if le.RealIP != "" {
		return le.RealIP
	}
	return le.RemoteAddr
}

// ========================== Process ============================================================

// Process evaluates the compiled WAF rules against event + resolver chain and
// applies the matched rule's action. Two-pass evaluation (Task H8):
//
//   - Pass 1: passRules.Match — a hit short-circuits the threat check. The event
//     is passed through unchanged (whitelisted). Pass-rules do NOT consult the
//     action map because their verdict is always "let it through".
//   - Pass 2: gateRules.Match — the threat check. On a hit the matched rule's
//     action (from the action map) is dispatched; on a miss the event is passed
//     through unchanged.
//
// The first matching rule in EACH pass wins (DECISION D12: first-match-wins is
// the natural RuleSet semantics). We never cross-contaminate the two RuleSets
// because Match returns a single verdict — passRules hit means we never call
// gateRules.Match for this event.
//
// Pass-rules check (len(passRules.Rules()) > 0) is the production-hot path: a
// config with zero pass-rules skips the first Match entirely, paying only the
// call-overhead of the no-rules check. RuleSet.Match on an empty RuleSet is a
// constant-time miss anyway, so the explicit guard is a stylistic optimisation
// rather than a correctness one.
//
// Action dispatch (DECISION D12 — engine returns verdict, plugin decides):
//
//	"drop"         → return (nil, nil)              — gate the event out
//	"tag"          → Level="THREAT:<rule>"; passthrough — flag for downstream
//	"tag:<suffix>" → Level="THREAT:<rule>:<suffix>"; passthrough — same, with
//	                  the suffix preserved so executor routing can read the rule's
//	                  intent from Level without consulting the rule table.
//
// Returns:
//
//	(event,    nil) — passthrough (no rule fired, or action="pass"/"tag"[/"tag:suffix"])
//	(nil,      nil) — drop path (gate rule fired with action="drop")
//	(nil,   ctx.Err()) — cancellation honored before any rule evaluation
func (p *WafProcessor) Process(ctx context.Context, event *plugin.Event) (*plugin.Event, error) {
	// ── Respect cancellation ──────────────────────────────────────────────────────────
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// ── Pass 1: whitelist check (short-circuit on hit) ───────────────────────────────
	// passRules is never nil (NewRuleSetFromConfig always returns a non-nil
	// RuleSet; the empty case is "zero rules, all misses"). The Rules() length
	// check is a small optimisation on the production-hot path: most WAF
	// configs have no pass-rules, so we skip the Match call entirely.
	if len(p.passRules.Rules()) > 0 {
		if _, matched := p.passRules.Match(event, p.resolver); matched {
			// Whitelist hit — pass through unchanged. The matched pass-rule's
			// name is intentionally not exposed (no convention for it in
			// Envelope). A future hook could log it via the sidecar logFn if
			// the operator wants a paper trail of whitelist hits.
			return event, nil
		}
	}

	// ── Pass 2: threat check ─────────────────────────────────────────────────────────
	name, matched := p.gateRules.Match(event, p.resolver)
	if !matched {
		return event, nil
	}

	// ── Apply the matched gate-rule's action ──────────────────────────────────────────
	action := p.actions[name]
	switch {
	case action == ActionDrop:
		if p.scoreFn != nil && p.dropScore > 0 {
			if ip := clientIP(event); ip != "" {
				p.scoreFn(ip, p.dropScore)
			}
		}
		return nil, nil
	case action == ActionTag:
		event.Envelope.Level = "THREAT:" + name
		return event, nil
	case strings.HasPrefix(action, "tag:"):
		// tag:<suffix> — preserve the suffix so downstream sinks / executors
		// can route on the rule's intent (e.g. "tag:rate-limit" vs
		// "tag:ban"). Signal the scorer with the label's weight from
		// tagWeights; missing label → no score signal (tag still fires).
		label := strings.TrimPrefix(action, "tag:")
		event.Envelope.Level = "THREAT:" + name + ":" + label
		if p.scoreFn != nil {
			if w := p.tagWeights[label]; w > 0 {
				if ip := clientIP(event); ip != "" {
					p.scoreFn(ip, w)
				}
			}
		}
		return event, nil
	default:
		// Unknown action value — fail-closed (drop) rather than fail-open
		// (silent passthrough). For a WAF gate the safer outcome is to gate
		// the event out. classifyAction rejects unknown actions at Init, so
		// reaching this branch means either a corruption in the action map
		// or a future Action* constant that the dispatcher was not updated
		// for — both should surface as a hard drop, not a silent pass.
		return nil, nil
	}
}
