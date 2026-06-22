// ====== Module: pkg/sink/stdout — Manifest ======
//   Plugin manifest for the stdout sink plugin.
//   Declares plugin ID, version, role, and I/O types.

package stdout

import "github.com/mr-addams/arx-core/pkg/plugin"

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
