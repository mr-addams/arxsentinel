// ========================== Bruteforce manifest =======================================
//   Identity and data contract for the bruteforce detector plugin.

package bruteforce

import "github.com/mr-addams/arxsentinel/pkg/plugin"

// Manifest describes the detector's interface contract and role in the pipeline.
func (d *bruteforceDetector) Manifest() plugin.Manifest {
	return plugin.Manifest{
		PluginID:      "bruteforce",
		PluginVersion: "1.0.0",
		Role:          plugin.RoleDetector,
		InputType:     plugin.TypeStructured,
		OutputType:    plugin.TypeStructured,
		Tags:          []string{"http", "rate-based", "bruteforce"},
	}
}
