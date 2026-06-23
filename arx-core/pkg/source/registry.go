// ========================== Module pkg/source/registry ==================================
//   Central registry for named source factories.
//   Each source implementation registers itself via init() so the pipeline can
//   instantiate sources by name from YAML config without a hard-coded factory list.
//
//   WHAT IS HERE:
//     InputConfig      — runtime config passed to Factory (independent type, not from internal/)
//     LineParser       — Parse(line) interface satisfied by *parser.CombinedParser, etc.
//     BuildOptions     — dependency injection for sources that need external state
//     Factory          — constructor signature: (InputConfig, BuildOptions) → Source
//     Register         — called from init() of each source file
//     Build            — instantiate by name
//     Names            — sorted list of registered names
//
//   WHAT IS NOT HERE:
//     Source implementations (file.go, stdin.go, ...) — each self-registers via init()
//     main.go bridging — if needed, main.go converts config.InputConfig → InputConfig
//
//   DEPENDENCY RULE:
//     This package imports only pkg/plugin, pkg/pluginregistry and stdlib.
//     No import from internal/ — external developers must be able to use this package.
//
//   GENERIC CORE (Flow 070 / Task 1.1.2):
//     Store + mutex + Register/Get/Names/Manifest* are delegated to a singleton
//     *pluginregistry.Registry[Factory, plugin.Manifest]. The thin Build() wrapper
//     stays here because its signature is source-specific (no ctx, no DI, no
//     fallback) — this is the "variadic logic stays in wrappers" rule from
//     Decision 2. The public API is preserved byte-for-byte: every package-level
//     function still has the same signature, so plugin init() call-sites
//     (file.go, stdin.go, http.go, syslog.go, exec/, sentinel/) compile unchanged.

package source

import (
	"fmt"
	"time"

	"github.com/mr-addams/arx-core/pkg/parser"
	"github.com/mr-addams/arx-core/pkg/plugin"
	"github.com/mr-addams/arx-core/pkg/pluginregistry"
)

// InputConfig — runtime config for a single source instance.
//
// Type field specifies the source type (e.g. "file", "stdin").
// Path is used by type="file"; ignored by other types.
// This type is independent of internal/config to avoid import cycles.
type InputConfig struct {
	Type           string // "file", "stdin", etc.
	Path           string // for type="file"; ignored for others
	Exec           string // path to exec plugin binary; used when type="exec"
	Addr           string // network address for type="syslog": "udp://:5514", "tcp://:514", "unix:///var/run/arx.sock"
	Mode           string // "push" | "pull"; for type="http"
	URL            string // for type="http" pull mode: full URL to poll
	HTTPPath       string // URL path for push handler, default "/"
	Token          string // optional Bearer token for auth
	TLSCert        string // path to TLS certificate file (for https://)
	TLSKey         string // path to TLS private key file (for https://)
	Protocol       string // envelope protocol: "plain"|"ndjson"|"cloudflare"|"firehose"|"pubsub"|"loki"|"otlp"|"azure"|"splunk"
	EnvelopeField  string // field name for ndjson envelope extraction
	PullInterval   string // polling interval for pull mode, e.g. "30s"
	MaxBodyBytes   int    // max request body size; default 10485760 (10MB)
	MaxConnections int    // max concurrent TCP connections; syslog only, default 0 = use defaultMaxConns (1000)
}

// LineParser — read-only view of a log line parser.
// Satisfied by *parser.CombinedParser, *parser.JSONParser, *parser.RegexParser
// and similar implementations living in pkg/parser.
//
// Defined here so pkg/source has no import dependency on internal/core/parser.
// Actual parser implementations satisfy this interface implicitly (Go structural typing).
type LineParser interface {
	// Parse parses a single log line and returns the parsed LogEntry.
	// ok=false if the line does not match the parser's expected format.
	Parse(line string) (*parser.LogEntry, bool)
}

// BuildOptions — external runtime dependencies injected into source factories.
//
// Parser is required and passed to sources that need to parse log lines.
// RetryInterval specifies the delay between retry attempts (used by file watchers, etc.).
// LogFn is an optional logging function; sources use it for operational logs.
// If LogFn is nil, sources should not log.
type BuildOptions struct {
	Parser        LineParser
	RetryInterval time.Duration
	LogFn         func(tag, msg, level string) // nil is allowed
}

// Factory — constructor function for a named source.
//
// Called by Build() to instantiate a source by name.
// Returns an error if the config is invalid or initialization fails.
type Factory func(cfg InputConfig, opts BuildOptions) (plugin.Source, error)

// defaultReg — package singleton holding all source factories and manifests.
// Lives across test runs in a single binary, which is why tests need a way to
// unregister their injected names (see unregisterForTest in registry_test.go).
var defaultReg = pluginregistry.NewRegistry[Factory, plugin.Manifest]()

// Register registers a Factory under name.
// Panics on duplicate registration — duplication is a programmer error caught at startup.
// Called from init() in each source file.
func Register(name string, f Factory) {
	defaultReg.Register(name, f)
}

// RegisterManifest stores a static Manifest under name, parallel to Register.
// Lets the validator read a source's data contract without constructing it
// (file/exec sources require a path and parser that are unavailable at validation time).
// Called from init() alongside Register in each source implementation.
func RegisterManifest(name string, m plugin.Manifest) {
	defaultReg.RegisterManifest(name, m)
}

// ManifestByName returns the static Manifest registered for name.
// Safe to call concurrently. No side-effects — does not construct any source.
func ManifestByName(name string) (plugin.Manifest, bool) {
	return defaultReg.ManifestByName(name)
}

// Build creates a source by name using the registered factory.
//
// Returns error when name is not registered or the factory fails.
func Build(name string, cfg InputConfig, opts BuildOptions) (plugin.Source, error) {
	f, ok := defaultReg.Get(name)
	if !ok {
		return nil, fmt.Errorf("pkg/source: unknown source %q; registered: %v", name, Names())
	}
	return f(cfg, opts)
}

// Names returns a sorted list of all registered source names.
// Safe to call concurrently.
func Names() []string {
	return defaultReg.Names()
}

// unregister removes the factory and manifest registered under name.
// Test-only helper: production code never deletes — Register/RegisterManifest
// are designed to be called once per name from init(), panicking on duplicates.
// Counterpart lives here (not in the generic core) because deletion is not
// part of the registry's public contract; only tests need it for idempotency
// under `go test -count>1`. Returns silently if name is not registered.
func unregister(name string) {
	defaultReg.Delete(name)
}
