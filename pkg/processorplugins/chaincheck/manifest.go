// ========================== pkg/processor/chaincheck — Manifest ============================
//   Manifest returns the processor's identity and data contract for the pipeline framework.

// ====== Module: chaincheck — manifest =========================================
//
//	Plugin identity and data contract for the chaincheck processor.
//	Declares: Role=Processor, Input=TypeStructured, Output=TypeStructured.
package chaincheck

import "github.com/mr-addams/arx-core/pkg/plugin"

// Manifest returns the processor's identity and data contract.
func (p *ChainCheckProcessor) Manifest() plugin.Manifest {
	return plugin.Manifest{
		PluginID:      "chaincheck",
		PluginVersion: "1.0.0",
		Role:          plugin.RoleProcessor,
		InputType:     plugin.TypeStructured,
		OutputType:    plugin.TypeStructured,
		Tags:          []string{"enrichment", "proxy-chain", "infrastructure"},
	}
}
