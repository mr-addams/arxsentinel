// ========================== Probe detector manifest =====================================
//
//	Manifest for the probe detector. Moved to sub-package to keep package detector
//	free of plugin-specific metadata once all detectors are migrated (Flow 076).
package probe

import "github.com/mr-addams/arx-core/pkg/plugin"

func (d *probeDetector) Manifest() plugin.Manifest {
	return plugin.Manifest{
		PluginID:      "probe",
		PluginVersion: "1.0.0",
		Role:          plugin.RoleDetector,
		InputType:     plugin.TypeStructured,
		OutputType:    plugin.TypeStructured,
		Tags:          []string{"http", "path-based", "sensitive-paths"},
	}
}
