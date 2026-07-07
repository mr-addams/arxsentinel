// ====== Module: cloudflare — manifest =============================================
//
//	Plugin identity and data contract for the Cloudflare executor.
//	Declares: Role=Executor, Input=TypeScoredEvent, Output=TypeNone.
package cloudflare

import "github.com/mr-addams/arx-core/pkg/plugin"

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
