// ========================= Module pkg/processor/registry ==================================
//   Central registry for named processor factories.
//   Each processor implementation registers itself via init() so the pipeline can
//   instantiate processors by name from YAML config without a hard-coded factory list.
//
//   WHAT IS HERE:
//     ProcessorConfig  — runtime config passed to Factory
//     Factory          — constructor signature: (ProcessorConfig) → plugin.Processor
//     Register         — called from init() of each processor file
//     Build            — instantiate by name; (nil,nil) when Enabled==false
//     Names            — sorted list of registered names
//
//   WHAT IS NOT HERE:
//     Processor implementations — each self-registers via init()
//
//   DEPENDENCY RULE:
//     This package imports only pkg/plugin, pkg/pluginregistry and stdlib.
//     No import from internal/ — external developers must be able to use this package.
//
//   GENERIC CORE (Flow 070 / Task 1.1.6):
//   Store + mutex + Register/Get/Names are delegated to a singleton
//   *pluginregistry.Registry[Factory, struct{}]. The thin Build() wrapper stays here
//   because its signature is processor-specific — the variadic aspect per Decision 2
//   lives in the wrapper, NOT in the generic core:
//     1. **nil-return on disabled** — when cfg.Enabled == false, Build returns
//        (nil, nil) without consulting the factory store. This short-circuit
//        must happen BEFORE the registry lookup; processors that have no
//        constructor still get a clean "off" path. The wrapper owns this logic.
//   Unlike detector/executor, processor has no execplugin fallback and no
//   SharedResources DI — those branches are absent here by design, not by
//   omission. See DECISIONS.md Flow 070 / 1.1.1 — processor (and detector)
//   parameterise M as struct{} because they expose no registry-level manifest
//   API (the Manifest comes from the plugin.Processor instance, not the
//   registry).
//
//   The public API is preserved byte-for-byte: every package-level function
//   still has the same signature, so plugin init() call-sites compile
//   unchanged.

package processor

import (
	"fmt"

	"github.com/mr-addams/arx-core/pkg/plugin"
	"github.com/mr-addams/arx-core/pkg/pluginregistry"
)

// ProcessorConfig — runtime config for a single processor instance.
//
// Enabled is extracted by the caller from the pipeline config.
// Params contains all remaining YAML fields for arbitrary processor-specific parameters.
type ProcessorConfig struct {
	Enabled bool
	Params  map[string]any
}

// Factory — constructor function for a named processor.
//
// Called by Build() only when cfg.Enabled == true.
// Returns (nil, nil) only if the implementation decides the processor should be disabled
// based on Params (e.g., invalid config with safe degradation). Most implementations
// should return an error for invalid params.
type Factory func(cfg ProcessorConfig) (plugin.Processor, error)

// defaultReg — package singleton holding all processor factories.
// Lives across test runs in a single binary; init()-registered plugin names are
// stable because each registers exactly once per process and Register panics on
// duplicates. Registry-level tests (registry_test.go) reset the singleton between
// runs via the test-only unregister() helper to stay idempotent under `go test -count>1`.
//
// M is parameterised as struct{}: the processor registry does not expose a
// registry-level manifest API (manifests are returned by the plugin.Processor
// instance via the Manifest() method, not by the registry), so the
// manifest-store half of the generic core stays empty. See DECISIONS.md
// Flow 070 / 1.1.1 — detector and processor use struct{} as the opaque M.
var defaultReg = pluginregistry.NewRegistry[Factory, struct{}]()

// Register registers a Factory under name.
// Panics on duplicate registration — duplication is a programmer error caught at startup.
// Called from init() in each processor file.
func Register(name string, f Factory) {
	defaultReg.Register(name, f)
}

// Build creates a processor by name using the registered factory.
//
// Returns (nil, nil) when cfg.Enabled == false — the caller must handle nil.
// Returns error when name is not registered.
// Returns (nil, error) when the factory itself fails.
//
// Behaviour preserved byte-for-byte from the pre-migration implementation:
//  1. nil-return (nil, nil) on cfg.Enabled == false — short-circuits BEFORE
//     the registry lookup so disabled processors cost zero store lookups.
//     This order is part of the contract: callers rely on the silent (nil, nil)
//     even for names that are not registered, as long as Enabled is false.
//  2. Registry lookup; error on unknown name with the same message format.
//  3. Factory invocation with cfg — no DI, no execplugin fallback (those
//     concerns do not exist for processor in this codebase).
func Build(name string, cfg ProcessorConfig) (plugin.Processor, error) {
	// Aspect (nil-return on disabled): short-circuit before consulting the
	// store. This must stay BEFORE the registry lookup — otherwise a
	// non-existent processor that is also disabled would surface
	// "unknown processor" instead of the silent (nil, nil) contract callers
	// rely on.
	if !cfg.Enabled {
		return nil, nil
	}

	f, ok := defaultReg.Get(name)
	if !ok {
		return nil, fmt.Errorf("pkg/processor: unknown processor %q; registered: %v", name, Names())
	}
	return f(cfg)
}

// Names returns a sorted list of all registered processor names.
// Safe to call concurrently.
func Names() []string {
	return defaultReg.Names()
}

// unregister removes the factory registered under name.
// Test-only helper: production code never deletes — Register is designed to be
// called once per name from init(), panicking on duplicates. Counterpart lives
// here (not in the generic core) because deletion is not part of the registry's
// public contract; only tests need it for idempotency under `go test -count>1`.
// Returns silently if name is not registered.
func unregister(name string) {
	defaultReg.Delete(name)
}
