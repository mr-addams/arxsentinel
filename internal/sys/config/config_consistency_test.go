// ========================== Config consistency tests ====================================
//   Cross-file consistency checks that catch drift between:
//     - .env.example documented defaults vs Go defaults in config.go
//     - Blocklist list names in config.yaml vs hardcoded names in pkg/detector/badbot.go
//     - Bot names in config.yaml whitelist.bots vs defaultBots() in config.go
//
//   These tests are in an external package (config_test) because they import the
//   config package — they verify the public API, not internals.

package config_test

import (
	"bufio"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/mr-addams/arxsentinel/internal/sys/config"
)

// findRepoRoot returns the repository root directory using runtime.Caller.
// Test file is at internal/sys/config/config_consistency_test.go → ../../.. is the repo root.
func findRepoRoot(t *testing.T) string {
	t.Helper()
	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(testFile), "../../..")
}

// ========================== Test 1: .env.example defaults vs Go defaults ================

// TestEnvExampleDefaults verifies that every documented default value in
// deploy/container/docker/.env.example matches the Go default from defaultConfig().
//
// If someone changes a default in config.go but forgets to update .env.example,
// this test catches it by setting each documented env var and checking whether
// the resulting config differs from the pure default.
func TestEnvExampleDefaults(t *testing.T) {
	repoRoot := findRepoRoot(t)
	envPath := filepath.Join(repoRoot, "deploy/container/docker/.env.example")

	// Isolate from any ARXSENTINEL_* vars that may be set in CI or the caller's shell.
	// Without this, the baseline would include those overrides and every subsequent
	// comparison would produce false positives.
	// t.Cleanup restores each var after the test finishes.
	for _, env := range os.Environ() {
		if strings.HasPrefix(env, "ARXSENTINEL_") {
			k, v, _ := strings.Cut(env, "=")
			os.Unsetenv(k)
			// Go 1.22+: range loop vars are per-iteration — closure captures correctly.
			t.Cleanup(func() { os.Setenv(k, v) })
		}
	}

	f, err := os.Open(envPath)
	if err != nil {
		t.Fatalf("opening .env.example: %v", err)
	}
	defer f.Close()

	// Baseline: pure Go defaults — computed once, reused for every var check.
	// No env vars are set at this point, so this equals a clean defaultConfig().
	baseline, err := config.LoadConfig("/nonexistent/arxsentinel-test-env-example.yaml")
	if err != nil {
		t.Fatalf("LoadConfig baseline: %v", err)
	}

	// Pattern: "# ARXSENTINEL_<VAR>=<value>"
	re := regexp.MustCompile(`^# (ARXSENTINEL_[A-Z_]+)=(.+)$`)
	scanner := bufio.NewScanner(f)

	for scanner.Scan() {
		line := scanner.Text()
		m := re.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		varName := m[1]
		varValue := m[2]

		// Skip empty values — nothing to validate.
		if varValue == "" {
			continue
		}
		// Skip placeholders containing "$" (e.g. bcrypt hash).
		if strings.Contains(varValue, "$") {
			continue
		}
		// Skip CSV examples containing "," (e.g. IP lists).
		if strings.Contains(varValue, ",") {
			continue
		}
		// Skip paths and CIDRs containing "/".
		if strings.Contains(varValue, "/") {
			continue
		}
		// Skip explicitly marked example values (line ends with "# (example)").
		// Use this marker in .env.example for vars that show illustrative values
		// rather than actual Go defaults (e.g. ARXSENTINEL_METRICS_USERNAME=prometheus).
		if strings.Contains(line, "# (example)") {
			continue
		}

		// Set env var to the value documented in .env.example.
		os.Setenv(varName, varValue)

		// Config loaded with the single env var set.
		got, err := config.LoadConfig("/nonexistent/arxsentinel-test-env-example.yaml")

		// Clean up BEFORE checking the error — env must be restored even on failure.
		os.Unsetenv(varName)

		if err != nil {
			t.Errorf("LoadConfig with %s=%q failed: %v "+
				"(if this is an example value, add '# (example)' suffix to the line in .env.example)",
				varName, varValue, err)
			continue
		}

		// If setting this var to the documented value produces a different config,
		// the documented default does not match the Go default in config.go.
		if !reflect.DeepEqual(baseline, got) {
			t.Errorf(".env.example %s=%q does not match Go default — "+
				"update config.go default or .env.example value to keep them in sync",
				varName, varValue)
		}
	}

	if err := scanner.Err(); err != nil {
		t.Fatalf("scanning .env.example: %v", err)
	}
}

// ========================== Test 2: blocklist names in config.yaml =====================

// TestBlocklistNamesInConfigYAML verifies that "badbot-ua" and "badbot-ref" list names
// used in pkg/detector/badbot.go exist in config.yaml blocklist.lists section.
//
// If the detector hardcodes a list name and the config uses a different name,
// the detector silently finds no patterns — no error is returned.
func TestBlocklistNamesInConfigYAML(t *testing.T) {
	repoRoot := findRepoRoot(t)
	cfgPath := filepath.Join(repoRoot, "cookbook/config.reference.yaml")

	cfg, err := config.LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig(%s): %v", cfgPath, err)
	}

	// Collect all list names from config.yaml blocklist.lists.
	names := make(map[string]bool, len(cfg.Blocklist.Lists))
	for _, l := range cfg.Blocklist.Lists {
		names[l.Name] = true
	}

	if !names["badbot-ua"] {
		t.Error("blocklist.lists: missing \"badbot-ua\" — " +
			"pkg/detector/badbot.go hardcodes this name in Detect()")
	}
	if !names["badbot-ref"] {
		t.Error("blocklist.lists: missing \"badbot-ref\" — " +
			"pkg/detector/badbot.go hardcodes this name in Detect()")
	}
}

// ========================== Test 3: bot names consistency ===============================

// TestDefaultBotsMatchConfigYAML verifies that bot names in defaultBots() in config.go
// match bot names in config.yaml whitelist.bots.
//
// If a bot is added to defaultBots() but not config.yaml (or vice versa), the deployed
// config has different defaults than the code, which is confusing for operators.
func TestDefaultBotsMatchConfigYAML(t *testing.T) {
	repoRoot := findRepoRoot(t)

	// Load Go defaults (no config file).
	defaultCfg, err := config.LoadConfig("/nonexistent/arxsentinel-test-botsync.yaml")
	if err != nil {
		t.Fatalf("LoadConfig defaults: %v", err)
	}

	// Load config.yaml.
	cfgPath := filepath.Join(repoRoot, "cookbook/config.reference.yaml")
	fileCfg, err := config.LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig(%s): %v", cfgPath, err)
	}

	// Build name sets.
	defaultNames := make(map[string]bool, len(defaultCfg.Whitelist.Bots))
	for _, b := range defaultCfg.Whitelist.Bots {
		defaultNames[b.Name] = true
	}

	fileNames := make(map[string]bool, len(fileCfg.Whitelist.Bots))
	for _, b := range fileCfg.Whitelist.Bots {
		fileNames[b.Name] = true
	}

	// Every bot in defaultBots() must also be in config.yaml.
	for name := range defaultNames {
		if !fileNames[name] {
			t.Errorf("default bot %q is present in defaultBots() in config.go "+
				"but missing from config.yaml whitelist.bots", name)
		}
	}

	// Every bot in config.yaml must also be in defaultBots().
	for name := range fileNames {
		if !defaultNames[name] {
			t.Errorf("config.yaml whitelist.bots has bot %q but it is not "+
				"in defaultBots() in config.go", name)
		}
	}
}
