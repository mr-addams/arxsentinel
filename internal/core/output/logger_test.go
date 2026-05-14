// ========================== Tests output/logger =========================================

package output

import (
	"strings"
	"testing"
)

// ========================== Tests ThreatLogger ========================================

// TestLogDoesNotCallWriteFnOnEmpty verifies that writeFn is not called when level="".
func TestLogDoesNotCallWriteFnOnEmpty(t *testing.T) {
	called := false
	logger := NewThreatLogger(func(ip string, score int, level string, modules []string, reason string) {
		called = true
	})

	logger.Log("1.2.3.4", 30, "", []string{}, "")

	if called {
		t.Error("writeFn must not be called when level=\"\"")
	}
}

// TestLogCallsWriteFnOnWarn verifies that writeFn is called when level="WARN".
func TestLogCallsWriteFnOnWarn(t *testing.T) {
	called := false
	logger := NewThreatLogger(func(ip string, score int, level string, modules []string, reason string) {
		called = true
		if level != "WARN" {
			t.Errorf("level: expected WARN, got %q", level)
		}
	})

	logger.Log("1.2.3.4", 55, "WARN", []string{"probe"}, "env_probe:3")

	if !called {
		t.Error("writeFn must be called when level=\"WARN\"")
	}
}

// TestLogCallsWriteFnOnThreat verifies that writeFn is called when level="THREAT".
func TestLogCallsWriteFnOnThreat(t *testing.T) {
	called := false
	var capturedIP string
	var capturedScore int
	var capturedModules []string
	var capturedReason string

	logger := NewThreatLogger(func(ip string, score int, level string, modules []string, reason string) {
		called = true
		capturedIP = ip
		capturedScore = score
		capturedModules = modules
		capturedReason = reason
	})

	logger.Log("45.134.26.8", 85, "THREAT", []string{"probe", "rate", "ua"}, "probe:env:3,rate:142rps,ua:Nuclei")

	if !called {
		t.Fatal("writeFn must be called when level=\"THREAT\"")
	}
	if capturedIP != "45.134.26.8" {
		t.Errorf("ip: expected 45.134.26.8, got %q", capturedIP)
	}
	if capturedScore != 85 {
		t.Errorf("score: expected 85, got %d", capturedScore)
	}
	if len(capturedModules) != 3 {
		t.Errorf("modules: expected 3 elements, got %d", len(capturedModules))
	}
	if capturedReason == "" {
		t.Error("reason must not be empty")
	}
}

// ========================== Tests FormatThreatLine =====================================

// TestFormatThreatLineContainsRequiredFields verifies that the line contains all required fields.
func TestFormatThreatLineContainsRequiredFields(t *testing.T) {
	line := FormatThreatLine("1.2.3.4", 85, "THREAT", []string{"probe", "rate"}, "env_probe:3,rate:142rps")

	checks := []string{
		"THREAT",
		"1.2.3.4",
		"score=85",
		"modules=probe,rate",
		"reason=",
	}
	for _, check := range checks {
		if !strings.Contains(line, check) {
			t.Errorf("line does not contain %q: %s", check, line)
		}
	}
}

// TestFormatThreatLineWarnLevel verifies the format of a line with WARN level.
func TestFormatThreatLineWarnLevel(t *testing.T) {
	line := FormatThreatLine("10.0.0.1", 55, "WARN", []string{"ua"}, "curl")

	if !strings.Contains(line, "WARN") {
		t.Errorf("line must contain WARN: %s", line)
	}
	if !strings.Contains(line, "10.0.0.1") {
		t.Errorf("line must contain IP: %s", line)
	}
	if !strings.Contains(line, "score=55") {
		t.Errorf("line must contain score=55: %s", line)
	}
}

// TestFormatThreatLineTimestampRFC3339 verifies that the timestamp is in RFC3339 format.
func TestFormatThreatLineTimestampRFC3339(t *testing.T) {
	line := FormatThreatLine("1.2.3.4", 85, "THREAT", []string{"probe"}, "env")

	// RFC3339 starts with year YYYY- and contains T and Z
	parts := strings.SplitN(line, " ", 2)
	if len(parts) < 2 {
		t.Fatal("line does not contain a space")
	}
	ts := parts[0]
	if len(ts) < 20 {
		t.Errorf("timestamp too short for RFC3339: %q", ts)
	}
	if !strings.Contains(ts, "T") || !strings.Contains(ts, "Z") {
		t.Errorf("timestamp does not look like RFC3339: %q", ts)
	}
}

// TestFormatThreatLineEmptyModules verifies that an empty modules list does not cause a panic.
func TestFormatThreatLineEmptyModules(t *testing.T) {
	line := FormatThreatLine("1.2.3.4", 50, "WARN", []string{}, "")

	if !strings.Contains(line, "modules=") {
		t.Errorf("line must contain modules=: %s", line)
	}
}

// TestFormatThreatLineReasonWithSpecialChars verifies that a reason with special characters
// is formatted correctly and Fail2Ban failregex ("THREAT <HOST> score=\d+") still matches.
// reason=%q escapes quotes — we verify that the prefix "reason=" is present in the line.
func TestFormatThreatLineReasonWithSpecialChars(t *testing.T) {
	reason := `ua:"curl/8.7" path=/etc/passwd`
	line := FormatThreatLine("1.2.3.4", 85, "THREAT", []string{"ua", "probe"}, reason)

	// Fail2Ban failregex: "THREAT <HOST> score=\d+" — verify these parts are present
	for _, required := range []string{"THREAT", "1.2.3.4", "score=85", "reason="} {
		if !strings.Contains(line, required) {
			t.Errorf("line does not contain %q: %s", required, line)
		}
	}

	// reason must be wrapped in quotes (%q) — the line must contain "reason=\"
	if !strings.Contains(line, `reason="`) {
		t.Errorf("reason must be quoted (%q format): %s", "%q", line)
	}
}
