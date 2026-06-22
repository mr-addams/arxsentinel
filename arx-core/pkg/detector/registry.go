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
//     Build             — instantiate by name; (nil,nil) when Enabled==false; exec fallback
//     Names             — sorted list of registered names
//
//   WHAT IS NOT HERE:
//     Detector implementations (probe.go, rate.go, ...) — each self-registers via init()
//     main.go bridging — main.go converts config.DetectorConfig → DetectorConfig
//
//   DEPENDENCY RULE:
//     This package imports only pkg/plugin, pkg/pluginregistry, pkg/execplugin and stdlib.
//     No import from internal/ — external developers must be able to use this package.
//
//   GENERIC CORE (Flow 070 / Task 1.1.5):
//   Store + mutex + Register/Get/Names are delegated to a singleton
//   *pluginregistry.Registry[Factory, struct{}]. The thin Build() wrapper stays here
//   because its signature is detector-specific — most importantly, the three
//   variadic aspects per Decision 2 live in the wrapper, NOT in the generic core:
//     1. **SharedResources DI** — Build takes *SharedResources and passes it to the
//        opaque Factory. DI is Product-domain state; pulling it into the Core
//        registry type would violate ADR-002 boundary. Keeping it in the wrapper
//        keeps `F` opaque to the core.
//     2. **nil-return on disabled** — when cfg.Enabled == false, Build returns
//        (nil, nil) without consulting the factory store. This short-circuit
//        must happen BEFORE the registry lookup; detectors that have no
//        constructor still get a clean "off" path. The wrapper owns this logic.
//     3. **execplugin fallback** — when name is not registered but cfg.Exec is
//        set, Build spawns an ExecDetector via execplugin.NewDetector. The
//        context used is context.Background() — exec detectors manage their
//        own subprocess lifecycle (see exec/detector.go doc).
//   The public API is preserved byte-for-byte: every package-level function
//   still has the same signature, so plugin init() call-sites (probe, rate,
//   bruteforce, ...) compile unchanged.

package detector

import (
	"context"
	"fmt"

	"github.com/mr-addams/arx-core/pkg/execplugin"
	"github.com/mr-addams/arx-core/pkg/plugin"
	"github.com/mr-addams/arx-core/pkg/pluginregistry"
)

// DetectorConfig — runtime config for a single detector instance.
//
// Enabled is extracted by the caller (pipeline or main.go) from config.DetectorConfig.
// Params contains all remaining YAML fields captured via yaml:",inline" in config.DetectorConfig.
//
// main.go bridges config.DetectorConfig → DetectorConfig before calling Build().
// Consumer: pipeline.newDetector, main.go.
type DetectorConfig struct {
	Enabled bool                   // YAML: detectors[i].enabled, default false — whether to instantiate. Consumer: Build
	Params  map[string]interface{} // YAML: detectors[i].params.* — detector-specific config. Consumer: Factory
	Exec    string                 // YAML: detectors[i].exec — path to exec plugin binary; if set and name not in registry, build ExecDetector. Consumer: Build
}

// Matcher — read-only view of a blocklist, satisfied by *blocklist.Manager.
//
// Defined here so pkg/detector has no import dependency on internal/core/blocklist.
// *blocklist.Manager satisfies this interface implicitly (Go structural typing).
type Matcher interface {
	Match(list string, text string) bool
	// MatchResult returns (pattern, true) if the text matches a blocklist entry in the named list,
	// and the matched pattern is returned for inclusion in the reason field of DetectResult.
	// Returns ("", false) if no match is found.
	MatchResult(list string, text string) (string, bool)
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

// defaultReg — package singleton holding all detector factories.
// Lives across test runs in a single binary, which is why tests need a way to
// unregister their injected names (see unregisterForTest in registry_test.go).
//
// M is parameterised as struct{}: the detector registry does not expose a
// registry-level manifest API (manifests are returned by the detector
// instance via the plugin.Detector interface, not by the registry), so the
// manifest-store half of the generic core stays empty. See DECISIONS.md
// Flow 070 / 1.1.1 — detector (and processor) use struct{} as the opaque M.
var defaultReg = pluginregistry.NewRegistry[Factory, struct{}]()

// Register registers a Factory under name.
// Panics on duplicate registration — duplication is a programmer error caught at startup.
// Called from init() in each detector file.
func Register(name string, f Factory) {
	defaultReg.Register(name, f)
}

// Build creates a detector by name using the registered factory.
//
// Returns (nil, nil) when cfg.Enabled == false — the caller must handle nil.
// Returns error when name is not registered and cfg.Exec is empty.
// Returns an ExecDetector when name is not registered but cfg.Exec is set.
// Returns (nil, error) when the factory itself fails.
//
// ctx is accepted for parity with the original signature (and to leave room
// for future propagation into detectors that need pipeline context), but is
// not currently passed to the factory — the Factory type does not take a
// context. The exec fallback path explicitly uses context.Background()
// because exec detectors have an independent subprocess lifecycle.
//
// Behaviour preserved byte-for-byte from the pre-migration implementation:
//  1. nil-return (nil, nil) on cfg.Enabled == false — short-circuits BEFORE
//     registry lookup so disabled detectors cost zero store lookups.
//  2. Registry lookup, then execplugin fallback when name unknown AND
//     cfg.Exec != "" — same order, same error message, same context.
//  3. Factory invocation with (cfg, shared) — SharedResources DI stays in
//     the wrapper and is never observed by the generic core.
func Build(ctx context.Context, name string, cfg DetectorConfig, shared SharedResources) (plugin.Detector, error) {
	_ = ctx // accepted for signature parity; intentionally not propagated to the Factory type.

	// Aspect 2 (nil-return on disabled): short-circuit before consulting the
	// store. This must stay BEFORE the registry lookup — otherwise a
	// non-existent detector that is also disabled would surface "unknown
	// detector" instead of the silent (nil, nil) contract callers rely on.
	if !cfg.Enabled {
		return nil, nil
	}

	f, ok := defaultReg.Get(name)
	if !ok {
		// Aspect 3 (execplugin fallback): unknown name + cfg.Exec set →
		// ExecDetector. Uses Background context because exec detectors
		// manage their own subprocess lifecycle (see exec/detector.go).
		// Order matters: this branch must come BEFORE the "unknown detector"
		// error so a configured plugin binary always gets a chance to run,
		// even if its name is not pre-registered in the compiled binary.
		if cfg.Exec != "" {
			return execplugin.NewDetector(name, cfg.Exec, cfg.Params, context.Background())
		}
		return nil, fmt.Errorf("pkg/detector: unknown detector %q; registered: %v", name, Names())
	}

	// Aspect 1 (SharedResources DI): the opaque Factory is invoked with the
	// caller-provided SharedResources. The generic core never sees
	// SharedResources — it is Product/DI state and must not leak into Core
	// per ADR-002.
	return f(cfg, shared)
}

// Names returns a sorted list of all registered detector names.
// Safe to call concurrently.
func Names() []string {
	return defaultReg.Names()
}

// unregister removes the factory registered under name.
// Test-only helper: production code never deletes — Register is designed to
// be called once per name from init(), panicking on duplicates. Counterpart
// lives here (not in the generic core) because deletion is not part of the
// registry's public contract; only tests need it for idempotency under
// `go test -count>1`. Returns silently if name is not registered.
func unregister(name string) {
	defaultReg.Delete(name)
}
