// ========================== pkg/plugin — DataType constants ================================
//   DataType identifies the kind of data flowing between pipeline plugins.
//   Used in Manifest to declare input/output expectations; the pipeline validator
//   checks compatibility at startup (fail-fast on mismatch).

package plugin

// DataType identifies the kind of data flowing between pipeline plugins.
// Each plugin declares InputType and OutputType in its Manifest; the pipeline
// validator checks that adjacent plugins agree on the data shape.
type DataType string

const (
	TypeRawLog      DataType = "raw_log"      // raw access log line before parsing
	TypeStructured  DataType = "structured"   // parsed LogEntry with all HTTP fields
	TypeScoredEvent DataType = "scored_event" // LogEntry enriched with threat score
	TypeAny         DataType = "any"          // compatible with any DataType (universal bridge)
	TypeNone        DataType = "none"         // no data flowing (used for Sources that emit and Sinks that consume)
)
