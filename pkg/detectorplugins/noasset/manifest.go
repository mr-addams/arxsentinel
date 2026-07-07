// ========================== Detector manifests ==========================================
//
//	Each detector exposes a Manifest describing its identity, role, and data contract.
package noasset

import "github.com/mr-addams/arx-core/pkg/plugin"

func (d *noAssetDetector) Manifest() plugin.Manifest {
	return plugin.Manifest{
		PluginID:      "noasset",
		PluginVersion: "1.0.0",
		Role:          plugin.RoleDetector,
		InputType:     plugin.TypeStructured,
		OutputType:    plugin.TypeStructured,
		Tags:          []string{"http", "path-based", "no-asset"},
	}
}
