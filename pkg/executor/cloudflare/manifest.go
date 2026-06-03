// ========================== pkg/cloudflare — Manifest =====================================

package cloudflare

import "github.com/mr-addams/arxsentinel/pkg/plugin"

func (e *CloudflareExecutor) Manifest() plugin.Manifest {
	return plugin.Manifest{
		PluginID:      "cloudflare",
		PluginVersion: "1.0.0",
		Role:          plugin.RoleExecutor,
		InputType:     plugin.TypeScoredEvent,
		OutputType:    plugin.TypeNone,
		Tags:          []string{"cloudflare", "waf", "api"},
	}
}