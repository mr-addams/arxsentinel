package file

import "github.com/mr-addams/arxsentinel/pkg/plugin"

func (s *FileSink) Manifest() plugin.Manifest {
	return plugin.Manifest{
		PluginID:      "file",
		PluginVersion: "1.0.0",
		Role:          plugin.RoleSink,
		InputType:     plugin.TypeScoredEvent,
		OutputType:    plugin.TypeNone,
		Tags:          []string{"file", "fail2ban", "json", "log-rotation"},
	}
}