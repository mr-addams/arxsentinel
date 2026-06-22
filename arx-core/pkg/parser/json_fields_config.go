// ========================== pkg/parser — json_fields_config.go ============================
//   Pure DTO: nginx JSON log field name mapping.
//
//   WHAT IS HERE:
//     - JSONFieldsConfig — maps LogEntry fields to actual JSON key names in nginx log.
//
//   WHAT IS NOT HERE:
//     - Parser logic (parser.go, combined.go, json.go, regex.go, profiles.go).
//     - Methods or behavior — this is a passive data carrier.
//
//   Decision 9 (DECISIONS.md, Flow 074): relocated from internal/sys/config to pkg/parser
//   so json.go can move to Core (pkg/) without internal/ dependencies. internal/sys/config
//   keeps a type alias `type JSONFieldsConfig = parser.JSONFieldsConfig` for backward
//   compatibility — composite-literal call-sites (e.g. JSONFields: JSONFieldsConfig{...})
//   remain valid (Go spec: alias types are interchangeable).

package parser

// JSONFieldsConfig maps LogEntry fields to the actual JSON key names in the nginx log.
// Allows users to customize nginx log_format json without changing sentinel config structure.
// All fields default to standard nginx variable names.
type JSONFieldsConfig struct {
	RemoteAddr string `yaml:"remote_addr"` // default "remote_addr"
	Time       string `yaml:"time"`        // default "time_iso8601"
	Request    string `yaml:"request"`     // default "request" — "METHOD /uri PROTO" string
	Status     string `yaml:"status"`      // default "status"
	BytesSent  string `yaml:"bytes_sent"`  // default "bytes_sent"
	Referer    string `yaml:"referer"`     // default "http_referer"
	UserAgent  string `yaml:"user_agent"`  // default "http_user_agent"
	RealIP     string `yaml:"real_ip"`     // default "real_ip"
}
