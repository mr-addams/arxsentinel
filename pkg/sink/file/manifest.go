// ====== Module: pkg/sink/file — Manifest ======
//   Plugin manifest for the file sink plugin.
//   Declares plugin ID, version, role, and I/O types.
//   Tags: file, fail2ban, json, log-rotation.

package file

import "github.com/mr-addams/arx-core/pkg/plugin"

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
