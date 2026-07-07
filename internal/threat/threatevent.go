// ========================== internal/threat — ThreatEvent ===============
//
//	Product-owned threat event model. This type carries the scored result of a
//	pipeline evaluation: source IP, accumulated score, triggered detector
//	modules, human-readable reason, plus the transport metadata that travels
//	alongside it (timestamp, level, stream, source, source_type).
//
//	OWNERSHIP:
//	  internal/threat/ — product namespace, per Flow 083 principle P2:
//	  models belong to the plugin that emits them. The core runtime has no
//	  business knowing the ThreatEvent shape — it sees a generic *plugin.Event
//	  and reads Envelope fields for metrics only.
//
//	  Placed at the module-root internal/threat/ (not cmd/arxsentinel/internal/threat/)
//	  so that pkg/executorplugins/* (in particular the product-side executors
//	  cloudflare/mikrotik/nginx) can import it. Go's internal-package rule
//	  restricts internal/ visibility to the immediate parent subtree — the
//	  cmd/ subtree cannot be imported from pkg/.
//
//	MIGRATION (Flow 083, Gate B, RESOLVED-D strategy II):
//	  Moved verbatim from arx-core/pkg/plugin/sink.go as part of Task 3.3.
//	  Field order is byte-identical to the pre-Gate-B definition so JSON
//	  wire-format bytes are preserved (semantic compat per RESOLVED-Q8).
//
//	DEPENDENCY RULE:
//	  imports only stdlib (time). The pkg/plugin.Event envelope lives in
//	  arx-core and is composed by callers — this type itself does not
//	  reference pkg/plugin (zero coupling in either direction).
package threat

import "time"

// ThreatEvent — fully-populated threat event delivered to all Sinks after scoring.
//
// Migrated from arx-core/pkg/plugin/sink.go in Flow 083 Gate B (RESOLVED-Q2
// product-ownership). Field names match the pre-migration definition so the
// JSON wire format produced by pkg/sink/format/format.go (now obsolete here)
// and the consumer in cmd/arxsentinel/queue_event_source.go round-trips
// without byte changes.
//
// Boundary invariant: arx-core/pkg/ does NOT import internal/threat/
// (verified by rg). The ThreatEvent definition therefore lives here in
// product space and is referenced only by Formatter implementations and
// product code (processor_security, executors, queue_event_source).
type ThreatEvent struct {
	Timestamp  time.Time
	Level      string
	Stream     string
	Source     string
	SourceType string
	IP         string
	Score      int
	Modules    []string
	Reason     string
	RawLine    string
}
