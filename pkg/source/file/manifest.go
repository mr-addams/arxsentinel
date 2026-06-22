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
	}
}
