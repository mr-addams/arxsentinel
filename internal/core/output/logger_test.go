// ========================== Тесты output/logger =========================================

package output

import (
	"strings"
	"testing"
)

// ========================== Тесты ThreatLogger ========================================

// TestLogDoesNotCallWriteFnOnEmpty проверяет что при level="" writeFn не вызывается.
func TestLogDoesNotCallWriteFnOnEmpty(t *testing.T) {
	called := false
	logger := NewThreatLogger(func(ip string, score int, level string, modules []string, reason string) {
		called = true
	})

	logger.Log("1.2.3.4", 30, "", []string{}, "")

	if called {
		t.Error("writeFn не должен вызываться при level=\"\"")
	}
}

// TestLogCallsWriteFnOnWarn проверяет что при level="WARN" writeFn вызывается.
func TestLogCallsWriteFnOnWarn(t *testing.T) {
	called := false
	logger := NewThreatLogger(func(ip string, score int, level string, modules []string, reason string) {
		called = true
		if level != "WARN" {
			t.Errorf("level: ожидал WARN, получил %q", level)
		}
	})

	logger.Log("1.2.3.4", 55, "WARN", []string{"probe"}, "env_probe:3")

	if !called {
		t.Error("writeFn должен вызваться при level=\"WARN\"")
	}
}

// TestLogCallsWriteFnOnThreat проверяет что при level="THREAT" writeFn вызывается.
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
		t.Fatal("writeFn должен вызваться при level=\"THREAT\"")
	}
	if capturedIP != "45.134.26.8" {
		t.Errorf("ip: ожидал 45.134.26.8, получил %q", capturedIP)
	}
	if capturedScore != 85 {
		t.Errorf("score: ожидал 85, получил %d", capturedScore)
	}
	if len(capturedModules) != 3 {
		t.Errorf("modules: ожидал 3 элемента, получил %d", len(capturedModules))
	}
	if capturedReason == "" {
		t.Error("reason не должен быть пустым")
	}
}

// ========================== Тесты FormatThreatLine =====================================

// TestFormatThreatLineContainsRequiredFields проверяет что строка содержит все обязательные поля.
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
			t.Errorf("строка не содержит %q: %s", check, line)
		}
	}
}

// TestFormatThreatLineWarnLevel проверяет формат строки с уровнем WARN.
func TestFormatThreatLineWarnLevel(t *testing.T) {
	line := FormatThreatLine("10.0.0.1", 55, "WARN", []string{"ua"}, "curl")

	if !strings.Contains(line, "WARN") {
		t.Errorf("строка должна содержать WARN: %s", line)
	}
	if !strings.Contains(line, "10.0.0.1") {
		t.Errorf("строка должна содержать IP: %s", line)
	}
	if !strings.Contains(line, "score=55") {
		t.Errorf("строка должна содержать score=55: %s", line)
	}
}

// TestFormatThreatLineTimestampRFC3339 проверяет что временная метка в формате RFC3339.
func TestFormatThreatLineTimestampRFC3339(t *testing.T) {
	line := FormatThreatLine("1.2.3.4", 85, "THREAT", []string{"probe"}, "env")

	// RFC3339 начинается с года YYYY- и содержит T и Z
	parts := strings.SplitN(line, " ", 2)
	if len(parts) < 2 {
		t.Fatal("строка не содержит пробела")
	}
	ts := parts[0]
	if len(ts) < 20 {
		t.Errorf("временная метка слишком короткая для RFC3339: %q", ts)
	}
	if !strings.Contains(ts, "T") || !strings.Contains(ts, "Z") {
		t.Errorf("временная метка не выглядит как RFC3339: %q", ts)
	}
}

// TestFormatThreatLineEmptyModules проверяет что пустой список модулей не вызывает panic.
func TestFormatThreatLineEmptyModules(t *testing.T) {
	line := FormatThreatLine("1.2.3.4", 50, "WARN", []string{}, "")

	if !strings.Contains(line, "modules=") {
		t.Errorf("строка должна содержать modules=: %s", line)
	}
}

// TestFormatThreatLineReasonWithSpecialChars проверяет что reason со спецсимволами
// форматируется корректно и Fail2Ban failregex ("THREAT <HOST> score=\d+") всё ещё матчит.
// reason=%q экранирует кавычки — убеждаемся что prefix "reason=" в строке есть.
func TestFormatThreatLineReasonWithSpecialChars(t *testing.T) {
	reason := `ua:"curl/8.7" path=/etc/passwd`
	line := FormatThreatLine("1.2.3.4", 85, "THREAT", []string{"ua", "probe"}, reason)

	// Fail2Ban failregex: "THREAT <HOST> score=\d+" — проверяем что эти части присутствуют
	for _, required := range []string{"THREAT", "1.2.3.4", "score=85", "reason="} {
		if !strings.Contains(line, required) {
			t.Errorf("строка не содержит %q: %s", required, line)
		}
	}

	// reason должен быть обёрнут в кавычки (%q) — строка должна содержать "reason=\"
	if !strings.Contains(line, `reason="`) {
		t.Errorf("reason должен быть в кавычках (%q формат): %s", "%q", line)
	}
}
