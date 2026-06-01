package file

import "github.com/mr-addams/arxsentinel/pkg/plugin"

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