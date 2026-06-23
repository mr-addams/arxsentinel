// ========================== Module pkg/pluginregistry/registry_test =====================
//   Unit tests for the generic Registry[F, M] core.
//
//   CONCURRENCY NOTE:
//     Every test builds its own *Registry via NewRegistry — no global state,
//     no init()-side-effect coupling. This deliberately mirrors the pattern
//     established by Flow 070 / Task 1.1.0 ([068-1] fix): isolated instances
//     are what makes -count=N green.
//
//   TYPE CHOICE:
//     Tests use simple marker types (string for F, int for M) to keep the
//     surface readable. The whole point of generic core is that the types
//     are opaque to it — any F/M pair is valid.

package pluginregistry_test

import (
	"sort"
	"sync"
	"testing"

	"github.com/mr-addams/arx-core/pkg/pluginregistry"
)

// ---------------------------------------------------------------------------
// Register / Get
// ---------------------------------------------------------------------------

// TestRegisterAndGet: round-trip a factory through the registry.
func TestRegisterAndGet(t *testing.T) {
	r := pluginregistry.NewRegistry[string, int]()
	r.Register("alpha", "factory-A")

	got, ok := r.Get("alpha")
	if !ok {
		t.Fatalf("Get(alpha): expected ok=true, got false")
	}
	if got != "factory-A" {
		t.Fatalf("Get(alpha): got %q, want %q", got, "factory-A")
	}
}

// TestGetMissingReturnsZeroAndFalse: Get on an unknown name must return
// (zero, false) — no panic, no error string, just the zero value.
func TestGetMissingReturnsZeroAndFalse(t *testing.T) {
	r := pluginregistry.NewRegistry[string, int]()
	// Also register one to make sure missing lookup is not confused by an
	// empty map special case.
	r.Register("present", "x")

	got, ok := r.Get("absent")
	if ok {
		t.Fatalf("Get(absent): expected ok=false, got true (value=%q)", got)
	}
	if got != "" {
		t.Fatalf("Get(absent): expected zero value \"\", got %q", got)
	}
}

// TestGetOnEmptyRegistry: brand-new registry behaves like Get on a missing key.
func TestGetOnEmptyRegistry(t *testing.T) {
	r := pluginregistry.NewRegistry[int, int]()
	got, ok := r.Get("anything")
	if ok {
		t.Fatalf("Get on empty registry: expected ok=false, got true (value=%d)", got)
	}
	if got != 0 {
		t.Fatalf("Get on empty registry: expected zero value 0, got %d", got)
	}
}

// TestRegisterDuplicatePanics: a second Register under the same name is a
// programmer error and must panic — matches the existing host-registry contract.
func TestRegisterDuplicatePanics(t *testing.T) {
	r := pluginregistry.NewRegistry[string, int]()
	r.Register("dup", "first")

	defer func() {
		if rec := recover(); rec == nil {
			t.Fatalf("expected panic on duplicate Register, got none")
		}
	}()
	r.Register("dup", "second")
}

// ---------------------------------------------------------------------------
// Names
// ---------------------------------------------------------------------------

// TestNamesSorted: Names returns a sorted snapshot. Sorted because the
// existing five host registries sort (deterministic e2e/validator output).
func TestNamesSorted(t *testing.T) {
	r := pluginregistry.NewRegistry[string, int]()
	// Insert in non-sorted order to make sure the sort is internal,
	// not an artifact of map iteration order.
	r.Register("charlie", "c")
	r.Register("alpha", "a")
	r.Register("bravo", "b")

	names := r.Names()
	want := []string{"alpha", "bravo", "charlie"}
	if !equalSlices(names, want) {
		t.Fatalf("Names(): got %v, want %v", names, want)
	}
}

// TestNamesIsSnapshot: mutating the returned slice must not affect the registry.
// This is a contract guarantee for callers (host wrappers) that may stash the
// slice for logging.
func TestNamesIsSnapshot(t *testing.T) {
	r := pluginregistry.NewRegistry[string, int]()
	r.Register("only", "v")

	names := r.Names()
	names[0] = "MUTATED"

	again := r.Names()
	if again[0] != "only" {
		t.Fatalf("internal state was mutated through returned Names slice: got %q", again[0])
	}
}

// TestNamesOnEmpty: Names on an empty registry returns an empty (non-nil)
// slice — nil-vs-empty matters to range loops in the host wrappers.
func TestNamesOnEmpty(t *testing.T) {
	r := pluginregistry.NewRegistry[string, int]()
	names := r.Names()
	if names == nil {
		t.Fatalf("Names() on empty registry: got nil, want non-nil empty slice")
	}
	if len(names) != 0 {
		t.Fatalf("Names() on empty registry: got %v, want []", names)
	}
}

// ---------------------------------------------------------------------------
// Manifests
// ---------------------------------------------------------------------------

// TestRegisterAndLookupManifest: manifests are stored and looked up
// independently of factories. A name can have a factory only, a manifest only,
// or both — depending on how the host uses it.
func TestRegisterAndLookupManifest(t *testing.T) {
	r := pluginregistry.NewRegistry[string, int]()
	r.RegisterManifest("alpha", 42)

	got, ok := r.ManifestByName("alpha")
	if !ok {
		t.Fatalf("ManifestByName(alpha): expected ok=true, got false")
	}
	if got != 42 {
		t.Fatalf("ManifestByName(alpha): got %d, want 42", got)
	}
}

// TestManifestByNameMissing: missing manifest returns (zero, false).
func TestManifestByNameMissing(t *testing.T) {
	r := pluginregistry.NewRegistry[string, int]()
	r.RegisterManifest("present", 1)

	got, ok := r.ManifestByName("absent")
	if ok {
		t.Fatalf("ManifestByName(absent): expected ok=false, got true (value=%d)", got)
	}
	if got != 0 {
		t.Fatalf("ManifestByName(absent): expected zero value 0, got %d", got)
	}
}

// TestManifestByNameOnEmpty: brand-new registry returns (zero, false).
func TestManifestByNameOnEmpty(t *testing.T) {
	r := pluginregistry.NewRegistry[string, int]()
	got, ok := r.ManifestByName("x")
	if ok {
		t.Fatalf("ManifestByName on empty registry: expected ok=false")
	}
	if got != 0 {
		t.Fatalf("ManifestByName on empty registry: expected zero value 0, got %d", got)
	}
}

// TestManifestWithoutFactory: a manifest can be registered without a factory
// (host wrappers may register contracts for plugins that are not yet built
// at validation time — see Flow 046).
func TestManifestWithoutFactory(t *testing.T) {
	r := pluginregistry.NewRegistry[string, int]()
	r.RegisterManifest("declared-only", 7)

	if _, ok := r.Get("declared-only"); ok {
		t.Fatalf("Get(declared-only) after only RegisterManifest: expected ok=false")
	}
	if got, ok := r.ManifestByName("declared-only"); !ok || got != 7 {
		t.Fatalf("ManifestByName(declared-only): got (%d, %v), want (7, true)", got, ok)
	}
}

// TestRegisterDuplicateManifestPanics: duplicate manifest is a programmer error.
func TestRegisterDuplicateManifestPanics(t *testing.T) {
	r := pluginregistry.NewRegistry[string, int]()
	r.RegisterManifest("dup", 1)

	defer func() {
		if rec := recover(); rec == nil {
			t.Fatalf("expected panic on duplicate RegisterManifest, got none")
		}
	}()
	r.RegisterManifest("dup", 2)
}

// ---------------------------------------------------------------------------
// Independence of factory and manifest stores
// ---------------------------------------------------------------------------

// TestFactoryAndManifestAreIndependent: a Register for name X does NOT
// affect ManifestByName(X) and vice versa. Important because the host
// wrappers register them in two separate init() calls and the two stores
// could be trivially confused otherwise.
func TestFactoryAndManifestAreIndependent(t *testing.T) {
	r := pluginregistry.NewRegistry[string, int]()
	r.Register("x", "factory-X")
	// No RegisterManifest for "x".

	if _, ok := r.ManifestByName("x"); ok {
		t.Fatalf("ManifestByName(x) returned ok=true after only Register: expected false")
	}
	if _, ok := r.Get("x"); !ok {
		t.Fatalf("Get(x) returned ok=false after Register: expected true")
	}
}

// ---------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------

// TestConcurrentRegisterAndGet: hammer the registry from many goroutines.
// Run with `go test -race` — must not report any data race. Combined with
// `go test -count=3` (Flow 070 / Task 1.1.0 unlocked it) this is the
// regression net for embedding into host registries in 1.1.2–1.1.6.
//
// Each goroutine registers a unique-per-iteration name to avoid duplicate-
// registration panics. Half the goroutines also probe via Get while
// registration is in flight — that's the actual race surface.
func TestConcurrentRegisterAndGet(t *testing.T) {
	const (
		workers    = 16
		iterations = 200
	)
	r := pluginregistry.NewRegistry[int, int]()

	var wg sync.WaitGroup
	wg.Add(workers)

	for w := 0; w < workers; w++ {
		workerID := w
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				// Unique key per (worker, iteration) tuple — no
				// duplicate-registration panics regardless of goroutine
				// interleaving.
				key := "w" + intToStr(workerID) + "-" + intToStr(i)
				r.Register(key, workerID)
				// Read path racing against the writes from the other
				// goroutines — same registry, names this goroutine
				// has not necessarily registered yet.
				_, _ = r.Get(key)
			}
		}()
	}
	wg.Wait()

	// Sanity: every (worker, iteration) tuple produced exactly one name.
	names := r.Names()
	want := workers * iterations
	if len(names) != want {
		t.Fatalf("expected %d registered names, got %d", want, len(names))
	}
	// Names must be sorted (contract).
	if !sort.StringsAreSorted(names) {
		t.Fatalf("Names() not sorted: %v (first/last: %q/%q)",
			names, names[0], names[len(names)-1])
	}
}

// TestConcurrentManifestAccess: same shape as Register/Get, for the
// manifest store. Kept separate so a failure points at the right store.
func TestConcurrentManifestAccess(t *testing.T) {
	const (
		workers    = 16
		iterations = 200
	)
	r := pluginregistry.NewRegistry[int, int]()

	var wg sync.WaitGroup
	wg.Add(workers)

	for w := 0; w < workers; w++ {
		workerID := w
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				key := "m" + intToStr(workerID) + "-" + intToStr(i)
				r.RegisterManifest(key, workerID)
				_, _ = r.ManifestByName(key)
			}
		}()
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------
// Opaque-type sanity: F and M are any, including a function value.
// ---------------------------------------------------------------------------

// TestFactoryTypeAsFunc: the core treats F as opaque. A function value
// stored under Register must come back identically through Get.
func TestFactoryTypeAsFunc(t *testing.T) {
	r := pluginregistry.NewRegistry[func(int) int, struct{}]()
	want := func(n int) int { return n * 2 }
	r.Register("doubler", want)

	got, ok := r.Get("doubler")
	if !ok {
		t.Fatalf("Get(doubler): expected ok=true")
	}
	if got(21) != 42 {
		t.Fatalf("Get(doubler)(21): got %d, want 42", got(21))
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// equalSlices reports whether a and b are exactly equal (length and elements).
// Avoids pulling in reflect.DeepEqual for a simple case.
func equalSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// intToStr formats a non-negative int without importing strconv into the
// test surface (keeps the import set small). Panics on negative — a guard,
// not a public API; the only caller in this file uses it for worker IDs.
func intToStr(n int) string {
	if n < 0 {
		panic("intToStr: negative input")
	}
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
