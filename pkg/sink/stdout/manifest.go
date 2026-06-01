package stdout

import "github.com/mr-addams/arxsentinel/pkg/plugin"

func (s *StdoutSink) Manifest() plugin.Manifest {
	return plugin.Manifest{
		PluginID:      "stdout",
		PluginVersion: "1.0.0",
		Role:          plugin.RoleSink,
		InputType:     plugin.TypeScoredEvent,
		OutputType:    plugin.TypeNone,
		Tags:          []string{"stdout", "console"},
	}
}