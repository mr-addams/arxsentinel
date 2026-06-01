package sentinel

import "github.com/mr-addams/arxsentinel/pkg/plugin"

func (s *SentinelThreatSink) Manifest() plugin.Manifest {
	return plugin.Manifest{
		PluginID:      "sentinel-threat",
		PluginVersion: "1.0.0",
		Role:          plugin.RoleSink,
		InputType:     plugin.TypeScoredEvent,
		OutputType:    plugin.TypeNone,
		Tags:          []string{"sentinel", "hub-bridge", "executor-queue"},
	}
}