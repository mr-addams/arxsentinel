// ========================== Module adapters/registry ===================================
//   Open registry for HTTP protocol adapters.
//   Each adapter implementation registers itself via init() so the HTTP source
//   can instantiate adapters by name from YAML config without a hard-coded
//   factory list — mirrors the pattern of pkg/source/registry.go (Flow 070).
//
//   WHAT IS HERE:
//     AdapterConfig — minimal runtime context passed to factories.
//                     Decouples this package from pkg/source/http (no import cycle).
//     Factory       — constructor signature: (AdapterConfig) → (Adapter, error)
//     Register      — called from init() in each adapter file
//     Build         — instantiate by name
//     Names         — sorted listing (used by parseProtocol validation)
//     Has           — boolean lookup (cheaper than Build for validation)
//
//   WHAT IS NOT HERE:
//     Adapter implementations (generic, vendor-specific, ...) — each self-registers
//     Source-specific glue (buildAdapter switch) — replaced by Build() call.
//
//   DEPENDENCY RULE:
//     This package imports only pkg/pluginregistry and stdlib.
//     No import from internal/ — external developers must be able to add new adapters.

package adapters

import (
	"fmt"

	"github.com/mr-addams/arx-core/pkg/plugin"
	"github.com/mr-addams/arx-core/pkg/pluginregistry"
)

// AdapterConfig — minimal runtime context passed to an adapter factory.
//
// Holds only the fields that vary per-protocol configuration. Today this is just
// EnvelopeField for the NDJSON protocol; new per-protocol fields go here.
type AdapterConfig struct {
	// EnvelopeField is the JSON key to extract from each NDJSON line.
	// Used by GenericAdapter in NDJSON mode; ignored by all other adapters.
	EnvelopeField string
}

// Factory — constructor function for a named adapter.
//
// Called by Build() to instantiate an adapter by name.
// Returns an error if the adapter cannot be initialized.
type Factory func(cfg AdapterConfig) (Adapter, error)

// defaultReg — package singleton holding all adapter factories.
// Lives across test runs in a single binary, which is why tests need a way to
// unregister their injected names (see unregisterForTest in registry_test.go
// when added). Production code never deletes — Register is designed to be
// called once per name from init(), panicking on duplicates.
var defaultReg = pluginregistry.NewRegistry[Factory, plugin.Manifest]()

// Register registers a Factory under name.
// Panics on duplicate registration — duplication is a programmer error caught
// at startup. Called from init() in each adapter file.
func Register(name string, f Factory) {
	defaultReg.Register(name, f)
}

// Build creates an adapter by name using the registered factory.
//
// Returns an error when name is not registered or the factory fails.
func Build(name string, cfg AdapterConfig) (Adapter, error) {
	f, ok := defaultReg.Get(name)
	if !ok {
		return nil, fmt.Errorf("adapters: unknown protocol %q; registered: %v", name, Names())
	}
	return f(cfg)
}

// Names returns a sorted list of all registered adapter names.
// Safe to call concurrently.
func Names() []string {
	return defaultReg.Names()
}

// Has reports whether a factory is registered under name.
// Cheaper than Build when only validation is needed (e.g. parseProtocol).
func Has(name string) bool {
	_, ok := defaultReg.Get(name)
	return ok
}
