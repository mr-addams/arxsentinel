// ========================== pkg/plugin — Manifest declaration ==============================
//   Manifest describes a plugin's identity and data contract for the pipeline framework.
//   It is populated from the plugin's embedded metadata at registration time and validated
//   by the pipeline bootstrapper before any data flows.

package plugin

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
}
