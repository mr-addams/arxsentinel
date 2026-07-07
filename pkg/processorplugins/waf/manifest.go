// ========================== pkg/processor/waf — Manifest ===================================
//
//	Plugin identity and data contract for the WAF processor (Flow 001, Group H).
//
//	Manifest declares the `http.*` field namespace produced by this plugin's resolver
//	(DECISION D7, D8). Every FieldDecl carries a Type (per D8.1) so the rule engine's
//	scheme knows how to type-check expressions written against these fields.
//
//	Name convention: FieldDecl.Name is the unqualified name within the "http"
//	namespace. D7 reserves the dot for the namespace separator only — sub-paths
//	like uri.path would be flattened to "uri_path" here (or aliased to a single
//	name like "path"). The Catalog's validName gate rejects dots inside the name,
//	so flattening is enforced at the Manifest level. See the comment on
//	resolver.go for the mapping back to LogEntry fields.
package waf

import "github.com/mr-addams/arx-core/pkg/plugin"

// Manifest is the plugin identity and data contract for the WAF processor.
//
// The Produces list mirrors the fields the HttpResolver (resolver.go) can answer for
// a *parser.LogEntry payload. All fields are Required=false because the WAF plugin
// reads Payload, not upstream — a missing field surfaces as a resolver miss, not a
// pipeline contract violation. PluginID is the registry name used in
// processor.Register("waf", factory) and in pipeline config YAML.
var Manifest = plugin.Manifest{
	PluginID:      "waf",
	PluginVersion: "1.0.0",
	Role:          plugin.RoleProcessor,
	InputType:     plugin.TypeStructured,
	OutputType:    plugin.TypeStructured,
	Tags:          []string{"waf", "rules", "security"},
	Produces: []plugin.FieldDecl{
		// HTTP request surface — populated by parser.LogEntry.
		//
		// Each Name is the bare unqualified name within the "http" namespace,
		// so expressions reference these as e.g. `http.method`, `http.path`,
		// `http.real_ip`. The mapping back to LogEntry's struct fields (where
		// the parser model carries nested structure under Path / Query /
		// RawURI / RemoteUser) is documented in resolver.go's resolveHTTP.
		{Name: "method", Type: plugin.TypeString},
		{Name: "path", Type: plugin.TypeString},
		{Name: "query", Type: plugin.TypeString},
		{Name: "raw_uri", Type: plugin.TypeString},
		{Name: "status", Type: plugin.TypeInt},
		{Name: "bytes_sent", Type: plugin.TypeInt},
		{Name: "referer", Type: plugin.TypeString},
		{Name: "user_agent", Type: plugin.TypeString},
		{Name: "remote_addr", Type: plugin.TypeIP},
		{Name: "real_ip", Type: plugin.TypeIP},
		{Name: "protocol", Type: plugin.TypeString},
		{Name: "remote_user", Type: plugin.TypeString},
	},
}
