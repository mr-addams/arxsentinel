// ========================== pkg/plugin — Manifest declaration ==============================
//   Manifest describes a plugin's identity and data contract for the pipeline framework.
//   It is populated from the plugin's embedded metadata at registration time and validated
//   by the pipeline bootstrapper before any data flows.

package plugin

// FieldDecl declares a single named field that a plugin either produces
// (emits in its output payloads) or consumes (requires in its input payloads).
//
// RESOLVED-Q4a (Flow 083) fixes the minimum viable shape: a Name plus a
// Required flag. The Type field is intentionally absent — it can be added in
// a later phase if the field-level validator ever needs to reason about field
// types beyond name-presence checks. Keeping the shape minimal preserves
// back-compat with existing plugins and avoids dragging in reflection-based
// schemas.
//
// A plugin that leaves Produces and Consumes nil declares "no field contract"
// — the pipeline bootstrapper treats it as compatible with any field shape.
// The field-level validator (Phase 4 of Flow 083) will check that for every
// adjacent consumer in the pipeline, producer.Produces is a superset of
// consumer.Consumes by Name (Required flag participates in the comparison).
type FieldDecl struct {
	// Name is the symbolic field identifier. Plugins agree on a Name spelling
	// when their data shapes overlap; mismatched Names are treated as
	// incompatible by the field-level validator.
	Name string

	// Required marks a field as mandatory for a consumer. A producer that
	// omits a Required field fails the field-level check at startup, surfacing
	// the mismatch before any data flows. Optional fields (Required == false)
	// are still listed in Consumes so consumers can use them when present.
	Required bool
}

// Manifest describes a plugin's identity and data contract.
// Every plugin exposes a Manifest so the pipeline framework can verify compatibility
// of roles and data types before starting data processing.
type Manifest struct {
	// PluginID is a unique identifier for the plugin within the pipeline.
	PluginID string
	// PluginVersion is the semantic version of the plugin.
	PluginVersion string
	// Role defines the plugin's position and responsibility in the pipeline.
	Role Role
	// InputType declares the DataType this plugin expects to receive.
	InputType DataType
	// OutputType declares the DataType this plugin produces after processing.
	OutputType DataType
	// Tags are free-form labels for selection and filtering in pipeline config.
	Tags []string

	// Produces declares the named fields this plugin emits in its output
	// payloads. A producer populates Produces so downstream consumers can
	// verify field-level compatibility. Leaving Produces nil preserves
	// back-compat with plugins that have not yet adopted field contracts —
	// the field-level validator treats nil as "no field contract declared".
	Produces []FieldDecl

	// Consumes declares the named fields this plugin requires (or accepts)
	// from its input payloads. A consumer that lists a field with
	// Required == true forces the field-level validator to fail-fast at
	// startup if no upstream producer emits that field. Leaving Consumes
	// nil preserves back-compat with plugins that have not yet adopted
	// field contracts.
	Consumes []FieldDecl
}
