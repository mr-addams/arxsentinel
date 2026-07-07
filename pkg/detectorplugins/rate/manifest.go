// ========================== Rate detector manifest ======================================
//
//	Manifest for the rate detector. Moved to sub-package to keep package detector
//	free of plugin-specific metadata once all detectors are migrated (Flow 076).
package rate

import "github.com/mr-addams/arx-core/pkg/plugin"

func (d *rateDetector) Manifest() plugin.Manifest {
	return plugin.Manifest{
		PluginID:      "rate",
		PluginVersion: "1.0.0",
		Role:          plugin.RoleDetector,
		InputType:     plugin.TypeStructured,
		OutputType:    plugin.TypeStructured,
		Tags:          []string{"http", "rate-based", "dos"},
	}
}
