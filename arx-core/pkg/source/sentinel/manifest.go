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
//	OutputType = TypeStructured — выдаёт *LogEntry, готовый для parser → processor chain → scoring
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
		// Produces declares the Envelope fields this source guarantees to populate.
		// Payload fields (Line, ...) are filled downstream by the parser and are NOT
		// declared here — the source only owns the transport envelope (Flow 083 P1).
		// Stream is filled by the engine from EventContext before downstream consumers
		// observe the Event; Level is filled later by the downstream scoring step,
		// so neither is set at Wrap time but both are guaranteed by the time the
		// Event flows on.
		Produces: []plugin.FieldDecl{
			{Name: "Timestamp", Required: true},
			{Name: "Stream", Required: true},
			{Name: "Source", Required: true},
			{Name: "SourceType", Required: true},
		},
	}
}
