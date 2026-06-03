// ========================== pkg/nginx — Manifest ========================================

package nginx

import "github.com/mr-addams/arxsentinel/pkg/plugin"

func (e *NginxExecutor) Manifest() plugin.Manifest {
	return plugin.Manifest{
		PluginID:      "nginx",
		PluginVersion: "1.0.0",
		Role:          plugin.RoleExecutor,
		InputType:     plugin.TypeScoredEvent,
		OutputType:    plugin.TypeNone,
		Tags:          []string{"nginx", "file-based"},
	}
}