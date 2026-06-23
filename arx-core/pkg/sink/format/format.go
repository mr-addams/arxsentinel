// ========================== pkg/sink/format — Formatter interface ===========================
//   Neutral serializer contract between core sinks and product code.
//
//   WHAT IS HERE:
//     - Formatter — minimal interface; Format(event *plugin.Event) ([]byte, error)
//
//   WHAT IS NOT HERE:
//     - Concrete Format* impls (Failban / JSON / SentinelThreat): moved to
//       product namespace cmd/arxsentinel/internal/threat/format in Gate B
//       (Flow 083, Task 3.3, RESOLVED-Q5b / RESOLVED-Z12). They format
//       product-shaped fields (Score / Modules / Reason) and therefore cannot
//       live in core without leaking product knowledge into the boundary.
//     - FormatFailban / FormatJSON / FormatSentinelThreat package-level
//       functions: obsolete post-Gate B — concrete sinks wire Formatter impls
//       from product. No core sink calls these directly anymore.
//
//   DEPENDENCY RULE:
//     pkg/sink/format → pkg/plugin (Event/Envelope types) + stdlib only.
//     No product imports allowed (boundary invariant verified by rg).
//
//   WHY A STANDALONE INTERFACE FILE:
//     Core sinks (pkg/sink/{file,stdout,sentinel}) hold a Formatter field and
//     call s.formatter.Format(event) on every Write. The interface is the
//     single point of contact between sink and serializer — keeping it
//     isolated in this file documents the boundary and prevents accidental
//     product imports.

package format

import "github.com/mr-addams/arx-core/pkg/plugin"

// Formatter — minimal serializer contract. Implementations turn an opaque
// *plugin.Event into the byte sequence the underlying sink writes out
// (Fail2Ban line, JSON envelope, sentinel-threat transport, …).
//
// Single method on purpose: narrow surface, cheap to mock, lets product
// code own every concrete byte format without touching core sink code.
//
// Product code supplies concrete impls (see cmd/arxsentinel/internal/threat/format
// for FailbanFormatter, JSONFormatter, SentinelFormatter). Core sinks accept
// the interface via constructor injection and call Format on every Write —
// they never inspect Event.Payload themselves (Gate B dissolved the Gate A
// type-assert pattern).
type Formatter interface {
	Format(event *plugin.Event) ([]byte, error)
}