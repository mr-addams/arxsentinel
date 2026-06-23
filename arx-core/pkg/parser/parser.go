// ========================== Module parser ===============================================
//   Shared types and Parser interface for all log format implementations.
//
//   WHAT IS HERE:
//     - LogEntry — canonical record of a parsed access log line (types.go)
//     - Parser   — interface implemented by CombinedParser and JSONParser
//
//   WHAT IS NOT HERE:
//     - Parsing logic (combined.go, json.go, regex.go)
//     - Logging (sys/utils)

package parser

// Parser is the interface for all access log format parsers.
// Each implementation parses one log format and returns a LogEntry.
type Parser interface {
	Parse(line string) (*LogEntry, bool)
}
