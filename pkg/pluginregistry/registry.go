// ========================== Module pkg/pluginregistry/registry ==========================
//   Generic plugin-registry core. See doc.go for package-level contract.
//
//   This file is intentionally tiny: store + RWMutex + six methods.
//   Anything that varies between the five host registries
//   (Build signature, context, DI, nil-on-disabled, execplugin fallback,
//   error formatting) lives in the host wrapper, NOT here.
//   See Flow 070 / Phase 1.1, Decision 2 (2026-06-21 revision).

package pluginregistry

import (
	"sort"
	"sync"
)

// Registry is a thread-safe, name-keyed store of plugin factories and their
// static manifests.
//
// F is the factory type the host registry registers (e.g. source.Factory).
// M is the manifest type the host registry stores alongside (e.g.
// plugin.Manifest, or struct{} for hosts that do not carry manifests).
//
// The core does not invoke F and does not inspect M; it only stores and
// returns values. Build logic stays in the host wrapper.
type Registry[F any, M any] struct {
	// mu guards both stores. Two maps under one mutex — they always grow
	// together (same caller registers both factory and manifest in init),
	// and a single mutex keeps the lock discipline simple and audit-friendly.
	mu        sync.RWMutex
	factories map[string]F
	manifests map[string]M
}

// NewRegistry returns an empty Registry ready for Register/RegisterManifest calls.
// Used by host wrappers; tests construct it directly for isolation.
func NewRegistry[F any, M any]() *Registry[F, M] {
	return &Registry[F, M]{
		factories: make(map[string]F),
		manifests: make(map[string]M),
	}
}

// Register stores factory f under name.
// Panics on duplicate registration — duplication is a programmer error caught
// at startup, matching the contract of the existing host registries.
func (r *Registry[F, M]) Register(name string, f F) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.factories[name]; exists {
		panic("pkg/pluginregistry: duplicate factory registration for " + name)
	}
	r.factories[name] = f
}

// Get returns the factory registered under name.
// The second return value is false when name is not registered; the factory
// value is the zero value of F in that case.
func (r *Registry[F, M]) Get(name string) (F, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	f, ok := r.factories[name]
	return f, ok
}

// Names returns a sorted snapshot of all registered factory names.
// Sorted for deterministic output (e2e/validator expects stable order).
// The returned slice is a fresh copy; mutating it does not affect the registry.
func (r *Registry[F, M]) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.factories))
	for n := range r.factories {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// RegisterManifest stores manifest m under name, parallel to Register.
// Hosts that do not carry manifests simply never call this — M is then
// parameterised as struct{} at the host site.
// Panics on duplicate registration — same contract as Register.
func (r *Registry[F, M]) RegisterManifest(name string, m M) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.manifests[name]; exists {
		panic("pkg/pluginregistry: duplicate manifest registration for " + name)
	}
	r.manifests[name] = m
}

// ManifestByName returns the static manifest registered for name.
// Safe to call concurrently. No side-effects — does not construct any
// factory or plugin instance. This is the static-contract lookup path
// used by arxsentinel validate (Flow 046).
func (r *Registry[F, M]) ManifestByName(name string) (M, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	m, ok := r.manifests[name]
	return m, ok
}

// Delete removes the factory and manifest registered under name.
// Counterpart to Register/RegisterManifest: production code typically
// registers once and never deletes (init-time wiring), but tests need
// cleanup between runs under `go test -count>1`, and hot-reload paths
// in future hosts can rely on the same primitive. Silent no-op if name
// is not registered.
func (r *Registry[F, M]) Delete(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.factories, name)
	delete(r.manifests, name)
}
