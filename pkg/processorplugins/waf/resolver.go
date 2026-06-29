// ========================== pkg/processor/waf — HTTP FieldResolver =========================
//   HttpResolver is the `http.*` namespace FieldResolver for the WAF processor (Flow 001,
//   Task H2). It implements rule.FieldResolver (DECISION D3), type-asserts the opaque
//   plugin.Event.Payload to the parser-owned *parser.LogEntry canonical form, and maps
//   each declared http.* field to its underlying accessor.
//
//   WHAT IS HERE:
//     - HttpResolver — stateless rule.FieldResolver implementation for http.*
//     - resolveHTTP  — internal dispatch table over LogEntry fields
//     - toIPValue    — net.ParseIP → rule.NewIP helper (centralised so the ip failure
//       behaviour is documented in one place)
//
//   WHAT IS NOT HERE:
//     - EnvelopeResolver (`core.*` namespace) — owned by pkg/rule/resolver.go
//     - The rule engine and Scheme — pkg/rule/{ruleset,builder}
//     - Action policy (drop / tag / pass) — WafProcessor.Process owns that decision
//
//   DEPENDENCY RULE:
//     pkg/processorplugins/waf → arx-core ({pkg/plugin, pkg/parser, pkg/rule}) + stdlib.
//     No imports from internal/* so this plugin stays hostable from any cmd/* binary.
//
//   CONCURRENCY:
//     HttpResolver carries no state (no fields). A single zero value may be shared
//     across goroutines without coordination, matching EnvelopeResolver's contract
//     (pkg/rule/resolver.go). The struct exists only to give the implementation a
//     discoverable name and to keep room for future per-instance configuration
//     (e.g. logger injection) without breaking the FieldResolver interface.
//
//   NAME CONVENTION NOTE:
//     DECISION D7 reserves the dot character for the namespace separator (e.g.
//     `http.method`). It does NOT permit dots inside a name; sub-structure like
//     LogEntry.Path / LogEntry.RawURI is flattened in the Manifest to "path" /
//     "raw_uri" so the Catalog accepts the registration (Catalog's validName gate
//     forbids '.' in the unqualified name). Both Manifest.Produces and the
//     resolveHTTP switch share this flat naming, so the two stay in lockstep.

package waf

import (
	"net"
	"strings"

	"github.com/mr-addams/arx-core/pkg/parser"
	"github.com/mr-addams/arx-core/pkg/plugin"
	"github.com/mr-addams/arx-core/pkg/rule"
	"github.com/mr-addams/arxsentinel/internal/threat"
)

// ========================== Namespace prefix ===============================================

// httpPrefix is the namespace prefix owned by this resolver (DECISION D7). Every field
// name HttpResolver accepts MUST be prefixed with this namespace; any other namespace
// returns (Value{}, false) so the dispatch chain (EnvelopeResolver + HttpResolver) can
// try each resolver in turn without ambiguity.
//
// Source of truth lives here, not in Manifest: the FieldDecl.Name entries in manifest.go
// carry the bare field name (e.g. "method"), and the namespace is fixed to "http" by
// PluginID. Resolver and Manifest therefore describe the same field set from two angles
// (consumer vs. producer) without duplicating "http." three places.
const httpPrefix = "http."

// ========================== HttpResolver ====================================================

// HttpResolver implements rule.FieldResolver for the `http.*` namespace.
//
// Behaviour matrix (mirrors pkg/rule.EnvelopeResolver):
//
//   - event == nil                       → (Value{}, false) — no panic, by contract
//   - field outside `http.*` namespace   → (Value{}, false) — different resolver's job
//   - field with no namespace dot        → (Value{}, false) — malformed field name
//   - unknown http.<field>               → (Value{}, false)
//   - non-*LogEntry, non-*ThreatEvent    → (Value{}, false) — payload is opaque; only
//     these two shapes carry HTTP data the WAF plugin knows about
//   - *LogEntry, known field             → (typed Value, true) — see resolveHTTP
//   - *LogEntry, ip field with invalid   → (Value{}, false) — toIPValue rejects
//     text in RealIP/RemoteAddr             malformed IP literals rather than substituting
//                                           the zero IP, because "match against 0.0.0.0"
//                                           is never the operator's intent
type HttpResolver struct{}

// Compile-time assertion: HttpResolver satisfies the FieldResolver interface.
// If the signature drifts, the build fails here — earlier and louder than at the first
// call site.
var _ rule.FieldResolver = HttpResolver{}

// Resolve implements FieldResolver for the `http.*` namespace.
//
// Field spelling: field is the fully-qualified dotted name as it appeared in the
// expression (e.g. "http.method"). Implementation matches the envelope resolver's
// CutPrefix-then-dispatch style so the dispatch chain is uniform.
func (HttpResolver) Resolve(field string, event *plugin.Event) (rule.Value, bool) {
	// Contract: nil event is a sentinel, not a crash trigger. Returning the zero
	// Value mirrors the "field unresolved" semantics so callers can treat it
	// uniformly with the unknown-field case.
	if event == nil {
		return rule.Value{}, false
	}

	// Fast reject for fields outside the http namespace before any string work.
	// Splitting once up-front keeps the hot path branch-light.
	rest, ok := strings.CutPrefix(field, httpPrefix)
	if !ok {
		return rule.Value{}, false
	}

	switch payload := event.Payload.(type) {
	case *parser.LogEntry:
		return resolveHTTP(rest, payload)
	case *threat.ThreatEvent:
		// ThreatEvent carries only the resolved IP — the rest of the HTTP
		// envelope is intentionally absent because scoring has already
		// collapsed the record. The WAF resolver only answers
		// http.real_ip for this payload shape; every other http.* field is
		// (Value{}, false). The compile-time Scheme will not have accepted
		// such expressions in most WAF profiles, but the runtime contract
		// still has to be defensive because ThreatEvent paths could
		// re-enter the WAF processor in future flows.
		if rest == "real_ip" {
			return toIPValue(payload.IP)
		}
		return rule.Value{}, false
	default:
		// Opaque Payload — not an HTTP record. The engine never inspects
		// Payload directly (D3), so this branch covers both "payload is
		// the wrong type" and "no payload at all".
		return rule.Value{}, false
	}
}

// ========================== resolveHTTP =====================================================

// resolveHTTP dispatches a namespace-stripped field name to the matching LogEntry
// accessor. Each branch wraps LogEntry's typed field in the corresponding rule.Value
// constructor — no reflection, no Payload reallocation.
//
// Adding a new http.* field requires:
//  1. Adding the FieldDecl here to manifest.go (so the Scheme knows about it).
//  2. Adding the case here.
//  3. Adding a table-driven case to resolver_test.go.
//
// The exhaustive switch (rather than a map) keeps resolveHTTP alloc-free on the hot
// path: a map lookup would require hashing the field name on every Resolve call.
func resolveHTTP(name string, entry *parser.LogEntry) (rule.Value, bool) {
	switch name {
	case "method":
		return rule.NewString(entry.Method), true
	case "path":
		return rule.NewString(entry.Path), true
	case "query":
		return rule.NewString(entry.Query), true
	case "raw_uri":
		return rule.NewString(entry.RawURI), true
	case "status":
		return rule.NewInt(int64(entry.Status)), true
	case "bytes_sent":
		return rule.NewInt(entry.BytesSent), true
	case "referer":
		return rule.NewString(entry.Referer), true
	case "user_agent":
		return rule.NewString(entry.UserAgent), true
	case "remote_addr":
		return toIPValue(entry.RemoteAddr)
	case "real_ip":
		return toIPValue(entry.RealIP)
	case "protocol":
		return rule.NewString(entry.Protocol), true
	case "remote_user":
		return rule.NewString(entry.RemoteUser), true
	default:
		// Unknown http.* field — the Scheme's compile-time check should
		// have caught this before traffic flows, so reaching here means
		// either a resolver registered for a field the Scheme doesn't
		// know about (a misconfiguration) or a stale expression after a
		// Manifest change.
		return rule.Value{}, false
	}
}

// ========================== toIPValue ========================================================

// toIPValue parses an IP literal and wraps it as a rule.NewIP value, or returns
// (Value{}, false) on parse failure. The empty string is treated as "no IP provided"
// and surfaces as (Value{}, false) rather than a zero-IP match — operators writing
// rules against http.real_ip expect "no real_ip" to differ from "real_ip=0.0.0.0".
//
// CIDR ("10.0.0.0/8") is intentionally NOT parsed as an IP — the rule engine has
// dedicated CIDR match operators that operate on KindIP values, and a CIDR string
// in LogEntry is a parser bug, not a normal case. Returning false on CIDR text makes
// the misconfiguration visible at the first evaluation rather than silently matching
// the network address.
func toIPValue(s string) (rule.Value, bool) {
	if s == "" {
		return rule.Value{}, false
	}
	if strings.Contains(s, "/") {
		// CIDR literal in a field meant to hold a single address.
		return rule.Value{}, false
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return rule.Value{}, false
	}
	return rule.NewIP(ip), true
}
