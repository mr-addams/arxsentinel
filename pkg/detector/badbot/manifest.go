// ========================== BadBot manifest ==============================================
//   Identity and data contract for the badbot detector plugin.

package badbot

import "github.com/mr-addams/arxsentinel/pkg/plugin"

// Manifest returns the plugin metadata for the badbot detector.
// Required by Manifestable; called from cmd/arxsentinel/validate.go when validating
// the plugin manifest registry.
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
