// ========================== pkg/processor — registry tests ================================
//   Tests: Register, Build (by name, disabled, unknown), Names, duplicate-panic,
//   nil-return-on-disabled contract.
//
//   Test-package convention follows pkg/sink and pkg/source (internal `package processor`):
//   we need access to the package-level unregister() helper so each test can clean
//   up the singleton via t.Cleanup — without this, `go test -count>1` re-runs the
//   same tests in the same binary and Register() would panic on a duplicate name
//   that the previous run left behind. See Flow 070 / Task 1.1.0 for the original
//   idempotency fix; this file mirrors that pattern for the processor registry.

package processor

import (
	"context"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/mr-addams/arx-core/pkg/plugin"
)

// unregisterForTest deletes every supplied name from the singleton registry.
// The unregister() helper itself is silent on unknown names, so passing the
// full set is safe even if a test panics before all registrations complete.
// t.Cleanup guarantees we run even on test failure / panic inside the body.
func unregisterForTest(names ...string) {
	for _, n := range names {
		unregister(n)
	}
}

// ── Mock Processor ────────────────────────────────────────────────────────────────────

// stubProcessor is the minimal plugin.Processor implementation for tests.
// We never call its methods; production code paths that exercise it are
// covered by the existing per-processor smoke tests in chaincheck/ and whitelist/.
type stubProcessor struct{}

func (s *stubProcessor) Name() string { return "stub" }
func (s *stubProcessor) Process(_ context.Context, _ *plugin.LogEntry) (*plugin.LogEntry, error) {
	return nil, nil
}
func (s *stubProcessor) Manifest() plugin.Manifest { return plugin.Manifest{} }

// ── Tests ──────────────────────────────────────────────────────────────────────────────

// TestRegistry_Names verifies that Names() contains the names we just registered
// and returns them in sorted order. We use unique per-test names (prefixed with
// the test name) so the assertion stays independent of any other test that may
// have left entries behind.
func TestRegistry_Names(t *testing.T) {
	names := []string{
		"test-names-zebra-" + t.Name(),
		"test-names-apple-" + t.Name(),
		"test-names-mango-" + t.Name(),
	}

	factory := func(cfg ProcessorConfig) (plugin.Processor, error) {
		return &stubProcessor{}, nil
	}

	for _, name := range names {
		Register(name, factory)
	}
	t.Cleanup(func() { unregisterForTest(names...) })

	got := Names()
	for _, name := range names {
		if !slices.Contains(got, name) {
			t.Errorf("Names() missing registered name %q; got %v", name, got)
		}
	}

	// Sorted-order guarantee — the generic core delegates to sort.Strings under the hood.
	sorted := slices.Clone(got)
	slices.Sort(sorted)
	if !slices.Equal(got, sorted) {
		t.Errorf("Names() is not sorted: got %v", got)
	}
}

// TestRegistry_Register verifies that a freshly-registered name resolves via
// Names() and that the factory we passed in is NOT invoked eagerly by Register.
// This guards against an eager-construction regression that would silently break
// disabled-config performance characteristics (Build must be the only entry point).
func TestRegistry_Register(t *testing.T) {
	name := "test-register-" + t.Name()

	called := false
	factory := func(cfg ProcessorConfig) (plugin.Processor, error) {
		called = true
		return &stubProcessor{}, nil
	}

	Register(name, factory)
	t.Cleanup(func() { unregisterForTest(name) })

	if !slices.Contains(Names(), name) {
		t.Fatalf("Names() does not contain freshly registered %q", name)
	}

	if called {
		t.Errorf("Register() invoked factory eagerly; factories must run only via Build()")
	}
}

// TestRegistry_Build_Disabled_ReturnsNilWithoutFactory is the core contract test
// for Flow 070 / Task 1.1.6. The processor.Build() wrapper MUST short-circuit on
// cfg.Enabled == false BEFORE consulting the factory store, returning (nil, nil).
// We verify both halves of the contract:
//  1. Returned values are (nil, nil).
//  2. The registered factory is NEVER invoked — the factory body calls t.Fatalf
//     so a regression that reaches the factory surfaces immediately.
func TestRegistry_Build_Disabled_ReturnsNilWithoutFactory(t *testing.T) {
	name := "test-disabled-" + t.Name()

	Register(name, func(cfg ProcessorConfig) (plugin.Processor, error) {
		// Reaching this point violates the nil-return-on-disabled contract.
		t.Fatalf("factory was invoked for disabled cfg; nil-return contract violated (cfg=%+v)", cfg)
		return nil, nil
	})
	t.Cleanup(func() { unregisterForTest(name) })

	p, err := Build(name, ProcessorConfig{Enabled: false})
	if err != nil {
		t.Fatalf("Build(disabled) error = %v, want nil", err)
	}
	if p != nil {
		t.Fatalf("Build(disabled) returned non-nil %v, want nil", p)
	}
}

// TestRegistry_Build_Disabled_UnknownName covers the same contract for the case
// where the name was never registered at all. Callers rely on the silent (nil, nil)
// for disabled processors even when the name is missing — otherwise disabling
// an unused processor would surface a spurious "unknown processor" error.
// Per registry.go doc: "the silent (nil, nil) even for names that are not
// registered, as long as Enabled is false."
func TestRegistry_Build_Disabled_UnknownName(t *testing.T) {
	unknownName := "test-disabled-unknown-" + t.Name()

	p, err := Build(unknownName, ProcessorConfig{Enabled: false})
	if err != nil {
		t.Fatalf("Build(disabled, unknown) error = %v, want nil (contract: short-circuit before lookup)", err)
	}
	if p != nil {
		t.Fatalf("Build(disabled, unknown) returned non-nil %v, want nil", p)
	}
}

// TestRegistry_Build_Unknown verifies the enabled-side error path: an enabled
// config with an unregistered name must surface a descriptive error rather than
// silently returning nil.
func TestRegistry_Build_Unknown(t *testing.T) {
	unknownName := "this-processor-does-not-exist-" + t.Name()

	p, err := Build(unknownName, ProcessorConfig{Enabled: true})
	if err == nil {
		t.Fatal("Build(unknown, enabled) expected error, got nil")
	}
	if p != nil {
		t.Fatalf("Build(unknown, enabled) returned non-nil %v, want nil", p)
	}
	if !strings.Contains(err.Error(), unknownName) {
		t.Errorf("error message does not mention unknown name %q: %v", unknownName, err)
	}
}

// TestRegistry_Register_Duplicate verifies that Register panics when the same
// name is registered twice. Duplicate registration is a programmer error — the
// init()-style flow means every test name must be unique or cleaned up, hence
// the explicit t.Cleanup below.
func TestRegistry_Register_Duplicate(t *testing.T) {
	duplicateName := "test-dup-" + t.Name()

	factory := func(cfg ProcessorConfig) (plugin.Processor, error) {
		return &stubProcessor{}, nil
	}

	Register(duplicateName, factory)
	t.Cleanup(func() { unregisterForTest(duplicateName) })

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("Register() should panic on duplicate name; got no panic")
		}
	}()

	Register(duplicateName, factory)
}

// TestRegistry_ConcurrentRegisterRead hammers the singleton with parallel
// Register / Names / Build calls to exercise the embedded *pluginregistry.Registry
// mutex. We never assert on specific semantics (other tests cover that); the
// goal is purely to surface any data race under `go test -race`.
//
// Each goroutine uses its own per-t.Name()-suffixed registration so concurrent
// runs do not collide. t.Cleanup runs once, after the goroutines have joined.
func TestRegistry_ConcurrentRegisterRead(t *testing.T) {
	const goroutines = 16

	names := make([]string, 0, goroutines)
	for i := 0; i < goroutines; i++ {
		// Use index in suffix (not rune arithmetic) so we are not limited to 26 entries.
		names = append(names, "test-concurrent-"+t.Name()+"-"+itoa(i))
	}

	factory := func(cfg ProcessorConfig) (plugin.Processor, error) {
		return &stubProcessor{}, nil
	}

	t.Cleanup(func() { unregisterForTest(names...) })

	var wg sync.WaitGroup
	wg.Add(goroutines * 3)

	// Writers
	for _, n := range names {
		go func(n string) {
			defer wg.Done()
			Register(n, factory)
		}(n)
	}

	// Readers — Names()
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_ = Names()
		}()
	}

	// Readers — Build(disabled) — exercises the short-circuit path under load
	for _, n := range names {
		go func(n string) {
			defer wg.Done()
			_, _ = Build(n, ProcessorConfig{Enabled: false})
		}(n)
	}

	wg.Wait()

	// Final Names() must contain every name we wrote. wg.Wait is a barrier,
	// so all Register() calls are visible to this read.
	final := Names()
	for _, n := range names {
		if !slices.Contains(final, n) {
			t.Errorf("post-concurrent Names() missing %q", n)
		}
	}
}

// itoa is a tiny base-10 integer formatter — avoids strconv import for one callsite.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}
