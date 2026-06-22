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
	}
}
