// ========================== pkg/plugin — Event (generic pipeline event) =================
//   Event is the generic unit that downstream plugin sinks and executor queues
//   will consume once the runtime migrates from concrete payload types to
//   opaque payloads (Flow 083, Phases 3 and 5). It composes an Envelope
//   (transport metadata, owned by the engine per P1) with a Payload (opaque
//   plugin-owned data, per P2/P3). The runtime never inspects or interprets
//   Payload; the owning plugin type-asserts it to its own type.
//
//   WHAT IS HERE:
//     - Event — value struct {Envelope; Payload any}
//
//   WHAT IS NOT HERE:
//     - Envelope transport fields — lives in envelope.go
//     - Concrete payload types — belong to plugins, never to pkg/plugin
//
//   DEPENDENCY RULE:
//     pkg/plugin → stdlib only.

package plugin

// Event is the generic pipeline event that Sink.Write and Executor.Pop will
// adopt once the runtime migrates from concrete payload types to opaque
// payloads (see Flow 083, Phases 3 and 5). For now it is a forward-looking
// type used to anchor the Envelope/Payload boundary in code; no existing
// sink or executor consumes it yet.
//
// Event carries an Envelope (transport metadata the engine may read for
// metrics/routing) plus an opaque Payload (plugin-owned data the engine
// MUST NOT interpret).
//
// Payload is typed as any on purpose: the engine never dereferences or type-
// asserts it. Each plugin owns its payload schema and is responsible for the
// type assertion inside its own boundaries:
//
//	if ev, ok := event.Payload.(*MyPluginEvent); ok { ... }
//
// Compatibility between producers and consumers will be verified at startup
// via the Manifest.InputType/OutputType checks already in place today, and
// (in a later phase) via a field-level validator that inspects Manifest field
// declarations.
//
// Event is a value type: copy on every read, no internal synchronization,
// safe for concurrent access by virtue of being immutable-by-convention after
// construction.
type Event struct {
	// Envelope carries transport metadata (Timestamp/Stream/Source/SourceType/
	// Level). See Envelope's doc-comment for the envelope/payload boundary
	// rationale (P1: engine owns only what it processes).
	Envelope

	// Payload is the plugin-owned opaque data block. It MUST NOT be inspected
	// by the engine or by plugins that did not produce it; the owning plugin
	// is the only party that type-asserts it to a concrete type. Plugins that
	// emit and consume payloads declare their shape via Manifest.InputType /
	// Manifest.OutputType (and, in a later phase, via field declarations).
	Payload any
}
