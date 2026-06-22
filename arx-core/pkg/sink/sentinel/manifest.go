// ====== Module: pkg/sink/sentinel — Manifest ======
//   Plugin manifest for the Sentinel Threat sink plugin.
//   Declares plugin ID, version, role, and I/O types.

package sentinel

import "github.com/mr-addams/arx-core/pkg/plugin"

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
