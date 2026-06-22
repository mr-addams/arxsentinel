// ========================== Module pkg/sink/registry ==================================
//   Central registry for named sink factories.
//   Each sink implementation registers itself via init() so the pipeline can
//   instantiate sinks by name from YAML config without a hard-coded factory list.
//
//   WHAT IS HERE:
//     SinkConfig      — runtime config passed to Factory (independent type, not from internal/)
//     Factory         — constructor signature: (ctx, SinkConfig) → Sink
//     Register        — called from init() of each sink file
//     Build           — instantiate by cfg.Type, propagating ctx
//     Names           — sorted list of registered names
//
//   WHAT IS NOT HERE:
//     Sink implementations (file.go, stdout.go, ...) — each self-registers via init()
//     main.go bridging — main.go converts config.SinkConfig → SinkConfig
//
//   DEPENDENCY RULE:
//     This package imports only pkg/plugin, pkg/pluginregistry and stdlib.
//     No import from internal/ — external developers must be able to use this package.
//
//   GENERIC CORE (Flow 070 / Task 1.1.3):
//     Store + mutex + Register/Get/Names/Manifest* are delegated to a singleton
//     *pluginregistry.Registry[Factory, plugin.Manifest]. The thin Build() wrapper
//     stays here because its signature is sink-specific (ctx propagation,
//     lookup by cfg.Type) — this is the "variadic logic stays in wrappers"
//     rule from Decision 2. The public API is preserved byte-for-byte: every
//     package-level function still has the same signature, so plugin init()
//     call-sites (stdout, file, exec, sentinel) compile unchanged.

package sink

import (
	"context"
	"fmt"

	"github.com/mr-addams/arx-core/pkg/plugin"
	"github.com/mr-addams/arx-core/pkg/pluginregistry"
)

// SinkConfig — runtime config for a single sink instance.
//
// Type field specifies the sink type (e.g. "file", "stdout").
// Path is used by type="file"; ignored by other types.
// Format specifies the output format (e.g. "fail2ban", "json").
// This type is independent of internal/config to avoid import cycles.
type SinkConfig struct {
	Type   string // "file", "stdout", "sentinel-threat", etc.
	Name   string // for type="sentinel-threat"; named channel binding
	Path   string // for type="file"; ignored for others
	Format string // "fail2ban", "json", etc.
	Exec   string // path to exec plugin binary; used when type="exec"
}

// Factory — constructor function for a named sink.
//
// Called by Build() to instantiate a sink by name. Receives the application
// context (Build's first argument) so sinks that perform blocking
// initialization (e.g. spawning a subprocess) can honour shutdown signals
// from the start.
// Returns an error if the config is invalid or initialization fails.
type Factory func(ctx context.Context, cfg SinkConfig) (plugin.Sink, error)

// defaultReg — package singleton holding all sink factories and manifests.
// Lives across test runs in a single binary, which is why tests need a way to
// unregister their injected names (see unregisterForTest in registry_test.go).
var defaultReg = pluginregistry.NewRegistry[Factory, plugin.Manifest]()

// Register registers a Factory under name.
// Panics on duplicate registration — duplication is a programmer error caught at startup.
// Called from init() in each sink file.
func Register(name string, f Factory) {
	defaultReg.Register(name, f)
}

// Build creates a sink by name using the registered factory.
//
// ctx is propagated to the factory so blocking initialization (e.g. spawning
// a subprocess) can honour shutdown signals from the start. Pass the
// application context, not context.Background().
//
// Returns error when name is not registered or the factory fails.
func Build(ctx context.Context, cfg SinkConfig) (plugin.Sink, error) {
	f, ok := defaultReg.Get(cfg.Type)
	if !ok {
		return nil, fmt.Errorf("pkg/sink: unknown sink %q; registered: %v", cfg.Type, Names())
	}
	return f(ctx, cfg)
}

// RegisterManifest stores a static Manifest under name, parallel to Register.
// Lets the validator read a sink's data contract without constructing it
// (file/exec sinks require a path that is unavailable at validation time).
// Called from init() alongside Register in each sink implementation.
func RegisterManifest(name string, m plugin.Manifest) {
	defaultReg.RegisterManifest(name, m)
}

// ManifestByName returns the static Manifest registered for name.
// Safe to call concurrently. No side-effects — does not construct any sink.
func ManifestByName(name string) (plugin.Manifest, bool) {
	return defaultReg.ManifestByName(name)
}

// Names returns a sorted list of all registered sink names.
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
