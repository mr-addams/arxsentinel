// ========================== Detector manifests ==========================================
//   Each detector exposes a Manifest describing its identity, role, and data contract.

package detector

import "github.com/mr-addams/arxsentinel/pkg/plugin"

func (d *uaDetector) Manifest() plugin.Manifest {
	return plugin.Manifest{
		PluginID:      "useragent",
		PluginVersion: "1.0.0",
		Role:          plugin.RoleDetector,
		InputType:     plugin.TypeStructured,
		OutputType:    plugin.TypeStructured,
		Tags:          []string{"http", "signature-based", "user-agent"},
	}
}

func (d *badBotDetector) Manifest() plugin.Manifest {
	return plugin.Manifest{
		PluginID:      "badbot",
		PluginVersion: "1.0.0",
		Role:          plugin.RoleDetector,
		InputType:     plugin.TypeStructured,
		OutputType:    plugin.TypeStructured,
		Tags:          []string{"http", "blocklist-based", "bad-bot"},
	}
}
