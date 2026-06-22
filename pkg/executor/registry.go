// ========================== pkg/executor/registry ================================
//   Central registry for named executor factories.
//   Each executor implementation registers itself via init() so the pipeline can
//   instantiate executors by name from YAML config without a hard-coded factory list.
//
//   WHAT IS HERE:
//     ExecutorConfig   — runtime config passed to Factory
//     Factory          — constructor signature: (ExecutorConfig, Logger) → Executor
//     Register         — called from init() of each executor file
//     Build            — instantiate by name; fallback to execplugin when type unknown
//     Names            — sorted list of registered names
//
//   WHAT IS NOT HERE:
//     Executor implementations — each self-registers via init()
//
//   DEPENDENCY RULE:
//     This package imports only pkg/plugin, pkg/pluginregistry, pkg/execplugin
//     and pkg/logger. No import from internal/ — external developers must be
//     able to use this package.
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
//
//   FLOW 073 TASK 1.3.1 — Logger injection (F1 closure):
//     Factory now accepts a pkg/logger.Logger. Build() forwards its log argument
//     to the registered factory, so cmd/arxsentinel can inject the real utils
//     bridge instead of each executor defaulting to logger.Nop. This is the
//     registry-side half of the executor logger restoration; factory-side and
//     cmd-side are updated in the same atomic commit (orchestration fix 1,
//     2026-06-22 — splitting them would leave a red-build intermediate state).

package executor

import (
	"fmt"

	"github.com/mr-addams/arx-core/pkg/execplugin"
	"github.com/mr-addams/arx-core/pkg/logger"
	"github.com/mr-addams/arx-core/pkg/plugin"
	"github.com/mr-addams/arx-core/pkg/pluginregistry"
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
// `log` is the operational logger injected by the caller (cmd/arxsentinel
// passes utils.AsLogger(); tests may pass logger.Nop). Flow 073 / Task 1.3.1 —
// this is the F1 closure channel that restores EXECUTOR-tag diagnostics after
// the registry stopped threading a logger through in pre-1.2 code. Returns a
// fully initialised plugin.Executor or an error.
type Factory func(cfg ExecutorConfig, log logger.Logger) (plugin.Executor, error)

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
//
// Flow 073 / Task 1.3.1: log is forwarded into the registered factory so
// the executor receives a real operational logger instead of falling back to
// logger.Nop inside the factory. The execplugin fallback path does NOT
// receive log — execplugin has its own logger contract wired at the
// execplugin layer (see Task 1.2.7 for executors; execplugin was migrated
// earlier in Flow 072).
func Build(cfg ExecutorConfig, log logger.Logger) (plugin.Executor, error) {
	f, ok := defaultReg.Get(cfg.Type)
	if !ok {
		// Exec fallback: if a plugin binary is configured, build an ExecExecutor.
		if cfg.Exec != "" {
			return execplugin.NewExecutor(cfg.Name, cfg.Exec, cfg.Params)
		}
		return nil, fmt.Errorf("pkg/executor: unknown executor type %q; registered: %v", cfg.Type, Names())
	}
	return f(cfg, log)
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
