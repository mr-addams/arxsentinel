// ========================== Detector manifest — crawler ===================================
//   Manifest for the crawler sub-package detector.

package crawler

import "github.com/mr-addams/arxsentinel/pkg/plugin"

func (d *crawlerDetector) Manifest() plugin.Manifest {
	return plugin.Manifest{
		PluginID:      "crawler",
		PluginVersion: "1.0.0",
		Role:          plugin.RoleDetector,
		InputType:     plugin.TypeStructured,
		OutputType:    plugin.TypeStructured,
		Tags:          []string{"http", "path-based", "sequential"},
	}
}
