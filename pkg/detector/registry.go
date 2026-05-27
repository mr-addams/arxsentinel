// ========================== Module pkg/detector/registry ================================
//   Central registry for named detector factories.
//   Each detector implementation registers itself via init() so the pipeline can
//   instantiate detectors by name from YAML config without a hard-coded factory list.
//
//   WHAT IS HERE:
//     DetectorConfig    — runtime config passed to Factory (bridged from config.DetectorConfig)
//     Matcher           — Match(list, text) interface satisfied by *blocklist.Manager
//     SharedResources   — dependency injection for detectors that need external state
//     Factory           — constructor signature: (DetectorConfig, SharedResources) → Detector
//     Register          — called from init() of each detector file
//     Build             — instantiate by name; (nil,nil) when Enabled==false
//     Names             — sorted list of registered names
//
//   WHAT IS NOT HERE:
//     Detector implementations (probe.go, rate.go, ...) — each self-registers via init()
//     main.go bridging — main.go converts config.DetectorConfig → DetectorConfig
//
//   DEPENDENCY RULE:
//     This package imports only pkg/plugin and stdlib.
//     No import from internal/ — external developers must be able to use this package.

package detector

import (
	"fmt"
	"sort"
	"sync"

	"github.com/mr-addams/arxsentinel/pkg/plugin"
)

// DetectorConfig — runtime config for a single detector instance.
//
// Enabled is extracted by the caller (pipeline or main.go) from config.DetectorConfig.
// Params contains all remaining YAML fields captured via yaml:",inline" in config.DetectorConfig.
//
// main.go bridges config.DetectorConfig → DetectorConfig before calling Build().
type DetectorConfig struct {
	Enabled bool
	Params  map[string]interface{} // arbitrary detector-specific parameters from YAML
}

// Matcher — read-only view of a blocklist, satisfied by *blocklist.Manager.
//
// Defined here so pkg/detector has no import dependency on internal/core/blocklist.
// *blocklist.Manager satisfies this interface implicitly (Go structural typing).
type Matcher interface {
	Match(list string, text string) bool
}

// SharedResources — external runtime dependencies injected into detector factories.
//
// Blocklist() returns nil when blocklist is not configured — detectors that depend on
// it (badbot) must handle a nil Matcher gracefully.
type SharedResources interface {
	Blocklist() Matcher
}

// Factory — constructor function for a named detector.
//
// Called by Build() only when cfg.Enabled == true.
// Returns (nil, nil) only if the implementation decides the detector should be disabled
// based on Params (e.g., invalid config with safe degradation). Most implementations
// should return an error for invalid params.
type Factory func(cfg DetectorConfig, shared SharedResources) (plugin.Detector, error)

var (
	mu        sync.RWMutex
	factories = map[string]Factory{}
)

// Register registers a Factory under name.
// Panics on duplicate registration — duplication is a programmer error caught at startup.
// Called from init() in each detector file.
func Register(name string, f Factory) {
	mu.Lock()
	defer mu.Unlock()
	if _, exists := factories[name]; exists {
		panic(fmt.Sprintf("pkg/detector: duplicate registration for %q", name))
	}
	factories[name] = f
}

// Build creates a detector by name using the registered factory.
//
// Returns (nil, nil) when cfg.Enabled == false — the caller must handle nil.
// Returns error when name is not registered.
// Returns (nil, error) when the factory itself fails.
func Build(name string, cfg DetectorConfig, shared SharedResources) (plugin.Detector, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	mu.RLock()
	f, ok := factories[name]
	mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("pkg/detector: unknown detector %q; registered: %v", name, Names())
	}
	return f(cfg, shared)
}

// Names returns a sorted list of all registered detector names.
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
