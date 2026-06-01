package stdin

import "github.com/mr-addams/arxsentinel/pkg/plugin"

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