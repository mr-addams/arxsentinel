// ========================== pkg/source/sentinel — Manifest ================================
//   Plugin metadata for the sentinel input source.
//   Declares plugin identity and data contract for the pipeline framework.

package sentinel

import "github.com/mr-addams/arx-core/pkg/plugin"

// Manifest возвращает plugin metadata для pipeline framework.
//
// Контракт данных:
//
//	InputType  = TypeNone     — source не принимает внешних данных (читает из NCS singleton)
//	OutputType = TypeStructured — выдаёт *LogEntry, готовый для parser → whitelist → scorer
//
// Теги отражают use case: "sentinel" (подсистема), "ncs" (Named Channel Switch),
// "pipeline-bridge" (связь двух pipeline'ов), "internal-bus" (внутри-процессная шина).
func (s *SentinelSource) Manifest() plugin.Manifest {
	return plugin.Manifest{
		PluginID:      "sentinel",
		PluginVersion: "1.0.0",
		Role:          plugin.RoleSource,
		InputType:     plugin.TypeNone,
		OutputType:    plugin.TypeStructured,
		Tags:          []string{"sentinel", "ncs", "pipeline-bridge", "internal-bus"},
	}
}
