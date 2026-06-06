// ========================== Module output/logger ========================================
//   Writing WARN/THREAT events to the threat log in Fail2Ban format.
//
//   WHAT IS HERE:
//     - ThreatLogger — accepts scorer verdict and writes a line to the log
//     - Log() — the only public function; does not write when level = "" (normal)
//
//   LINE FORMAT (read by Fail2Ban filter, Task 5.1):
//     2026-04-05T14:33:12Z THREAT 1.2.3.4 score=85 modules=probe,rate reason="..."
//
//   ISOLATION:
//     ThreatLogger does not import sys/utils directly — writeFn is injected
//     from main.go. In tests writeFn captures output into strings.Builder.
//
//   WHAT IS NOT HERE:
//     - Console logging (sys/utils.Log) — called via logFn in writeFn
//     - Score aggregation (scorer/)
//     - File opening (sys/utils.Init)

package output

import (
	"fmt"
	"strings"
	"time"
)

// ========================== ThreatLogger ==============================================

// ThreatLogger writes threat events to the threat log.
//
// YAML: output.threat_log.path (via injected writeFn). Consumer: pipeline (main.go).
type ThreatLogger struct {
	writeFn func(ip string, score int, level string, modules []string, reason string) // Internal — injected write function. Consumer: Log.
}

// NewThreatLogger creates a ThreatLogger with an injected write function.
//
// Called from: cmd/arxsentinel.main (pipeline setup).
// Non-blocking.
func NewThreatLogger(writeFn func(ip string, score int, level string, modules []string, reason string)) *ThreatLogger {
	return &ThreatLogger{writeFn: writeFn}
}

// Log writes a threat event if level is not empty (WARN or THREAT).
// When level = "" (normal activity) — returns silently without writing anything.
//
// Called from: pipeline (main.go post-scorer verdict).
// Non-blocking.
func (l *ThreatLogger) Log(ip string, score int, level string, modules []string, reason string) {
	if level == "" {
		return
	}
	l.writeFn(ip, score, level, modules, reason)
}

// ========================== Line formatting =====================================

// FormatThreatLine formats a single threat log line.
//
// Public function — used in tests to verify line format.
// utils.LogThreat formats the line independently (sys/ does not import core/).
// Format is compatible with Fail2Ban: timestamp level ip score=N modules=... reason="..."
//
// Example:
//
//	2026-04-05T14:33:12Z THREAT 1.2.3.4 score=85 modules=probe,rate reason="probe:env:3,rate:142rps"
func FormatThreatLine(ip string, score int, level string, modules []string, reason string) string {
	timestamp := time.Now().UTC().Format(time.RFC3339)
	modulesStr := strings.Join(modules, ",")
	return fmt.Sprintf("%s %s %s score=%d modules=%s reason=%q",
		timestamp, level, ip, score, modulesStr, reason)
}
