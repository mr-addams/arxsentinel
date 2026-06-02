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
//     This package imports only pkg/plugin and stdlib.
//     No import from internal/ — external developers must be able to use this package.

package processor

import (
	"fmt"
	"sort"
	"sync"

	"github.com/mr-addams/arxsentinel/pkg/plugin"
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

var (
	mu        sync.RWMutex
	factories = map[string]Factory{}
)

// Register registers a Factory under name.
// Panics on duplicate registration — duplication is a programmer error caught at startup.
// Called from init() in each processor file.
func Register(name string, f Factory) {
	mu.Lock()
	defer mu.Unlock()
	if _, exists := factories[name]; exists {
		panic(fmt.Sprintf("pkg/processor: duplicate registration for %q", name))
	}
	factories[name] = f
}

// Build creates a processor by name using the registered factory.
//
// Returns (nil, nil) when cfg.Enabled == false — the caller must handle nil.
// Returns error when name is not registered.
// Returns (nil, error) when the factory itself fails.
func Build(name string, cfg ProcessorConfig) (plugin.Processor, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	mu.RLock()
	f, ok := factories[name]
	mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("pkg/processor: unknown processor %q; registered: %v", name, Names())
	}
	return f(cfg)
}

// Names returns a sorted list of all registered processor names.
// Safe to call concurrently.
func Names() []string {
	mu.RLock()
	defer mu.RUnlock()
	names := make([]string, 0, len(factories))
	for n := range factories {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}