// ========================== Detector manifests ==========================================
//   Each detector exposes a Manifest describing its identity, role, and data contract.

package overflow

import "github.com/mr-addams/arx-core/pkg/plugin"

func (d *overflowDetector) Manifest() plugin.Manifest {
	return plugin.Manifest{
		PluginID:      "overflow",
		PluginVersion: "1.0.0",
		Role:          plugin.RoleDetector,
		InputType:     plugin.TypeStructured,
		OutputType:    plugin.TypeStructured,
		Tags:          []string{"http", "payload-based", "overflow"},
	}
}
