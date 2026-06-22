// ========================== UserAgent manifest =========================================
//   Identity and data contract for the useragent detector plugin.

package useragent

import "github.com/mr-addams/arx-core/pkg/plugin"

// Manifest returns the plugin metadata for the useragent detector.
// Required by Manifestable; called from cmd/arxsentinel/validate.go when validating
// the plugin manifest registry. PluginID intentionally stays "useragent"
// for historical compatibility with existing tooling.
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
