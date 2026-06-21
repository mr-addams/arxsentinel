// ========================== pkg/executor/registry ================================
//   Central registry for named executor factories.
//   Each executor implementation registers itself via init() so the pipeline can
//   instantiate executors by name from YAML config without a hard-coded factory list.
//
//   WHAT IS HERE:
//     ExecutorConfig   — runtime config passed to Factory
//     Factory          — constructor signature: (ExecutorConfig) → Executor
//     Register         — called from init() of each executor file
//     Build            — instantiate by name; fallback to execplugin when type unknown
//     Names            — sorted list of registered names
//
//   WHAT IS NOT HERE:
//     Executor implementations — each self-registers via init()
//
//   DEPENDENCY RULE:
//     This package imports only pkg/plugin, pkg/pluginregistry and pkg/execplugin.
//     No import from internal/ — external developers must be able to use this package.
//
//   GENERIC CORE (Flow 070 / Task 1.1.4):
//     Store + mutex + Register/Get/Names/Manifest* are delegated to a singleton
//     *pluginregistry.Registry[Factory, plugin.Manifest]. The thin Build() wrapper
//     stays here because its signature is executor-specific — most importantly,
//     the execplugin fallback (unknown name + cfg.Exec set → execplugin.NewExecutor)
//     is variadic logic per Decision 2 and lives in the wrapper, NOT in the generic
//     core. The public API is preserved byte-for-byte: every package-level function
//     still has the same signature, so plugin init() call-sites
//     (cloudflare, mikrotik, nginx, sentinel, exec/) compile unchanged.

package executor

import (
	"fmt"

	"github.com/mr-addams/arxsentinel/pkg/execplugin"
	"github.com/mr-addams/arxsentinel/pkg/plugin"
	"github.com/mr-addams/arxsentinel/pkg/pluginregistry"
)

// ExecutorConfig — runtime config for a single executor instance.
//
// Type is used to look up the registered factory.
// Exec is the path to an exec plugin binary; if set and Type is not registered,
// Build falls back to execplugin.NewExecutor.
type ExecutorConfig struct {
	Name   string                 `yaml:"name"`
	Type   string                 `yaml:"type"`
	Exec   string                 `yaml:"exec"`
	Params map[string]interface{} `yaml:"params"`
	// Config holds implementation-specific settings parsed by each executor itself.
	// Kept as raw map so pkg/executor has no import dependency on executor implementations.
	Config map[string]interface{} `yaml:"config"`
}

// Factory — constructor function for a named executor type.
//
// Called by Build() when the Type is found in the registry.
// Returns a fully initialised plugin.Executor or an error.
type Factory func(cfg ExecutorConfig) (plugin.Executor, error)

// defaultReg — package singleton holding all executor factories and manifests.
// Lives across test runs in a single binary, which is why tests need a way to
// unregister their injected names (see unregisterForTest in registry_test.go).
var defaultReg = pluginregistry.NewRegistry[Factory, plugin.Manifest]()

// Register registers a Factory under name.
// Panics on duplicate registration — duplication is a programmer error caught at startup.
// Called from init() in each executor implementation file.
func Register(name string, f Factory) {
	defaultReg.Register(name, f)
}

// Build creates an executor by type name using the registered factory.
//
// Returns error when name is not registered and cfg.Exec is empty.
// When name is not registered but cfg.Exec is non-empty, falls back to building
// an execplugin.ExecExecutor — this allows arbitrary plugin names without
// pre-registration in the compiled binary.
func Build(cfg ExecutorConfig) (plugin.Executor, error) {
	f, ok := defaultReg.Get(cfg.Type)
	if !ok {
		// Exec fallback: if a plugin binary is configured, build an ExecExecutor.
		if cfg.Exec != "" {
			return execplugin.NewExecutor(cfg.Name, cfg.Exec, cfg.Params)
		}
		return nil, fmt.Errorf("pkg/executor: unknown executor type %q; registered: %v", cfg.Type, Names())
	}
	return f(cfg)
}

// RegisterManifest stores a static Manifest under name, parallel to Register.
// Lets the validator read an executor's data contract without constructing it.
// Called from init() alongside Register in each executor implementation.
func RegisterManifest(name string, m plugin.Manifest) {
	defaultReg.RegisterManifest(name, m)
}

// ManifestByName returns the static Manifest registered for name.
// Safe to call concurrently. No side-effects — does not construct any executor.
func ManifestByName(name string) (plugin.Manifest, bool) {
	return defaultReg.ManifestByName(name)
}

// Names returns a sorted list of all registered executor type names.
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
