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
//     This package imports only pkg/plugin and pkg/execplugin.
//     No import from internal/ — external developers must be able to use this package.

package executor

import (
	"fmt"
	"sort"
	"sync"

	"github.com/mr-addams/arxsentinel/pkg/execplugin"
	"github.com/mr-addams/arxsentinel/pkg/plugin"
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

var (
	mu        sync.RWMutex
	factories = map[string]Factory{}
)

// Register registers a Factory under name.
// Panics on duplicate registration — duplication is a programmer error caught at startup.
// Called from init() in each executor implementation file.
func Register(name string, f Factory) {
	mu.Lock()
	defer mu.Unlock()
	if _, exists := factories[name]; exists {
		panic(fmt.Sprintf("pkg/executor: duplicate registration for %q", name))
	}
	factories[name] = f
}

// Build creates an executor by type name using the registered factory.
//
// Returns error when name is not registered and cfg.Exec is empty.
// When name is not registered but cfg.Exec is non-empty, falls back to building
// an execplugin.ExecExecutor — this allows arbitrary plugin names without
// pre-registration in the compiled binary.
func Build(cfg ExecutorConfig) (plugin.Executor, error) {
	mu.RLock()
	f, ok := factories[cfg.Type]
	mu.RUnlock()
	if !ok {
		// Exec fallback: if a plugin binary is configured, build an ExecExecutor.
		if cfg.Exec != "" {
			return execplugin.NewExecutor(cfg.Name, cfg.Exec, cfg.Params)
		}
		return nil, fmt.Errorf("pkg/executor: unknown executor type %q; registered: %v", cfg.Type, Names())
	}
	return f(cfg)
}

// Names returns a sorted list of all registered executor type names.
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
