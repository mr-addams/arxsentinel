// ====== Module: whitelist — manifest ==========================================
//
//	Plugin identity and data contract for the whitelist processor.
//	Declares: Role=Processor, Input=TypeStructured, Output=TypeStructured.
package whitelist

import "github.com/mr-addams/arx-core/pkg/plugin"

// Manifest is the plugin identity and data contract for the whitelist processor.
var Manifest = plugin.Manifest{
	PluginID:   "whitelist",
	Role:       plugin.RoleProcessor,
	InputType:  plugin.TypeStructured,
	OutputType: plugin.TypeStructured,
	Tags:       []string{"filter", "whitelist", "bot-verification"},
}
