// ========================== Module parser ===============================================
//   Shared types and Parser interface for all log format implementations.
//
//   WHAT IS HERE:
//     - LogEntry — type alias for plugin.LogEntry (canonical definition in pkg/plugin)
//     - Parser   — interface implemented by CombinedParser and JSONParser
//
//   WHAT IS NOT HERE:
//     - Parsing logic (combined.go, json.go)
//     - Logging (sys/utils)

package parser

import "github.com/mr-addams/arx-core/pkg/plugin"

// Parser is the interface for all access log format parsers.
// Each implementation parses one log format and returns a LogEntry.
type Parser interface {
	Parse(line string) (*LogEntry, bool)
}

// LogEntry is a type alias for plugin.LogEntry.
// All internal packages continue to use parser.LogEntry unchanged.
// The canonical definition and field documentation live in pkg/plugin/types.go.
type LogEntry = plugin.LogEntry
