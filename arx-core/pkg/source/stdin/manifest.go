// ========================== pkg/source/stdin — Manifest ========================================
//   Plugin metadata for the stdin source.
//   Describes identity and data contract for pipeline validation.

package stdin

import "github.com/mr-addams/arx-core/pkg/plugin"

// Manifest returns the stdin source's plugin metadata.
func (s *StdinSource) Manifest() plugin.Manifest {
	return plugin.Manifest{
		PluginID:      "stdin",
		PluginVersion: "1.0.0",
		Role:          plugin.RoleSource,
		InputType:     plugin.TypeNone,
		OutputType:    plugin.TypeStructured,
		Tags:          []string{"stdin", "pipe"},
		// Produces declares the Envelope fields this source guarantees to populate.
		// Payload fields (Line, ...) are filled downstream by the parser and are NOT
		// declared here — the source only owns the transport envelope (Flow 083 P1).
		// Stream is filled by the engine from EventContext before downstream consumers
		// observe the Event; Level is filled later by the product scorer, so neither
		// is set at Wrap time but both are guaranteed by the time the Event flows on.
		Produces: []plugin.FieldDecl{
			{Name: "Timestamp", Required: true},
			{Name: "Stream", Required: true},
			{Name: "Source", Required: true},
			{Name: "SourceType", Required: true},
		},
	}
}
