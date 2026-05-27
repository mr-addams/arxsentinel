// ========================== Module pkg/sink/registry ==================================
//   Central registry for named sink factories.
//   Each sink implementation registers itself via init() so the pipeline can
//   instantiate sinks by name from YAML config without a hard-coded factory list.
//
//   WHAT IS HERE:
//     SinkConfig      — runtime config passed to Factory (independent type, not from internal/)
//     Factory         — constructor signature: (SinkConfig) → Sink
//     Register        — called from init() of each sink file
//     Build           — instantiate by name
//     Names           — sorted list of registered names
//
//   WHAT IS NOT HERE:
//     Sink implementations (file.go, stdout.go, ...) — each self-registers via init()
//     main.go bridging — main.go converts config.SinkConfig → SinkConfig
//
//   DEPENDENCY RULE:
//     This package imports only pkg/plugin and stdlib.
//     No import from internal/ — external developers must be able to use this package.

package sink

import (
	"fmt"
	"sort"
	"sync"

	"github.com/mr-addams/arxsentinel/pkg/plugin"
)

// SinkConfig — runtime config for a single sink instance.
//
// Type field specifies the sink type (e.g. "file", "stdout").
// Path is used by type="file"; ignored by other types.
// Format specifies the output format (e.g. "fail2ban", "json").
// This type is independent of internal/config to avoid import cycles.
type SinkConfig struct {
	Type   string // "file", "stdout", etc.
	Path   string // for type="file"; ignored for others
	Format string // "fail2ban", "json", etc.
	Exec   string // path to exec plugin binary; used when type="exec"
}

// Factory — constructor function for a named sink.
//
// Called by Build() to instantiate a sink by name.
// Returns an error if the config is invalid or initialization fails.
type Factory func(cfg SinkConfig) (plugin.Sink, error)

var (
	mu        sync.RWMutex
	factories = map[string]Factory{}
)

// Register registers a Factory under name.
// Panics on duplicate registration — duplication is a programmer error caught at startup.
// Called from init() in each sink file.
func Register(name string, f Factory) {
	mu.Lock()
	defer mu.Unlock()
	if _, exists := factories[name]; exists {
		panic(fmt.Sprintf("pkg/sink: duplicate registration for %q", name))
	}
	factories[name] = f
}

// Build creates a sink by name using the registered factory.
//
// Returns error when name is not registered or the factory fails.
func Build(cfg SinkConfig) (plugin.Sink, error) {
	mu.RLock()
	f, ok := factories[cfg.Type]
	mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("pkg/sink: unknown sink %q; registered: %v", cfg.Type, Names())
	}
	return f(cfg)
}

// Names returns a sorted list of all registered sink names.
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
