// ========================== pkg/source/file — Manifest ========================================
//   Plugin metadata for the file source.
//   Describes identity and data contract for pipeline validation.

package file

import "github.com/mr-addams/arx-core/pkg/plugin"

// Manifest returns the file source's plugin metadata.
func (s *FileSource) Manifest() plugin.Manifest {
	return plugin.Manifest{
		PluginID:      "file",
		PluginVersion: "1.0.0",
		Role:          plugin.RoleSource,
		InputType:     plugin.TypeNone,
		OutputType:    plugin.TypeStructured,
		Tags:          []string{"file", "tail", "log-rotation"},
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
