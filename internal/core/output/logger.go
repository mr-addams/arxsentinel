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
// writeFn in production = utils.LogThreat (writes to threats.log + duplicates to console).
// writeFn in tests = function that captures output into a buffer for format verification.
type ThreatLogger struct {
	writeFn func(ip string, score int, level string, modules []string, reason string)
}

// NewThreatLogger creates a ThreatLogger with an injected write function.
// writeFn must ensure that a line is written to the threat log and console.
func NewThreatLogger(writeFn func(ip string, score int, level string, modules []string, reason string)) *ThreatLogger {
	return &ThreatLogger{writeFn: writeFn}
}

// Log writes a threat event if level is not empty (WARN or THREAT).
//
// When level = "" (normal activity) — returns silently without writing anything.
// This is the main filter: scorer calls Evaluate for every line, but only
// anomalous events are written to the log — otherwise threats.log would overflow.
//
// Called from the main pipeline after scorer.Evaluate.
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
