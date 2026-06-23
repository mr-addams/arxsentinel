// ========================== Module output/warnings ======================================
//   Writing chain-integrity infrastructure warnings to a dedicated file.
//
//   WHAT IS HERE:
//     WarningsWriter   — thread-safe file writer for CHAIN_WARN events
//     WriteChainWarning — formats and appends one warning line per CheckResult
//     Reopen           — closes and reopens the file descriptor (logrotate support)
//
//   LINE FORMAT (machine-readable, space-separated key=value):
//     2026-05-20T12:34:56Z CHAIN_WARN cloudflare-ip-as-client ip=1.2.3.4 cidr=104.16.0.0/13 log=/var/log/nginx/access.log
//     2026-05-20T12:34:56Z CHAIN_WARN bogon-ip-as-client ip=10.0.0.1 cidr=10.0.0.0/8 log=/var/log/apache/access.log
//
//   DISTINCTION FROM ThreatLogger:
//     ThreatLogger reports attacker activity (scored events, Fail2Ban-compatible).
//     WarningsWriter reports infrastructure misconfiguration — not an attack,
//     but a broken proxy chain that prevents ArxSentinel from seeing the real attacker IP.
//
//   WHAT IS NOT HERE:
//     Threat events (output/logger.go)
//     Console logging (sys/utils)
//     Score aggregation (scorer/)

package output

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/mr-addams/arxsentinel/internal/core/chaincheck"
)

// ========================== WarningsWriter ============================================

// WarningsWriter writes chain-integrity infrastructure warnings to a dedicated file.
// Thread-safe: concurrent WriteChainWarning calls are serialized with a mutex.
// The file is opened in append mode — safe for multi-process writes and logrotate.
//
// YAML: chain_guard.warnings_log (via path argument). Consumer: chaincheck (main.go).
type WarningsWriter struct {
	mu   sync.Mutex
	file *os.File // Internal — open file handle, nil after Close. Consumer: WriteChainWarning, Reopen, Close.
	path string   // Internal — file path for Reopen. Consumer: Reopen, Close.
}

// NewWarningsWriter opens path in append mode (O_CREATE|O_WRONLY|O_APPEND, 0644).
// Returns an error if the file cannot be created or opened.
//
// Called from: cmd/arxsentinel.main (pipeline setup, when chain_guard enabled).
// Non-blocking.
func NewWarningsWriter(path string) (*WarningsWriter, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("warnings writer: open %s: %w", path, err)
	}
	return &WarningsWriter{file: f, path: path}, nil
}

// WriteChainWarning appends one warning line for the given CheckResult.
// logFile identifies which access log produced the entry — essential for multi-log diagnostics.
// Thread-safe.
//
// Called from: chaincheck (main.go).
// Non-blocking.
func (w *WarningsWriter) WriteChainWarning(result *chaincheck.CheckResult, logFile string) error {
	line := formatChainWarningLine(result, logFile)

	w.mu.Lock()
	defer w.mu.Unlock()

	_, err := fmt.Fprintln(w.file, line)
	if err != nil {
		return fmt.Errorf("warnings writer: write: %w", err)
	}
	return nil
}

// Reopen closes and reopens the file — supports logrotate (SIGHUP handler).
// Data written before Reopen is preserved in the rotated file; writes after Reopen
// go to the new file. Thread-safe.
//
// Called from: SIGHUP handler (main.go).
// Blocking: write lock.
func (w *WarningsWriter) Reopen() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file != nil {
		_ = w.file.Sync()
		_ = w.file.Close()
		w.file = nil
	}

	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("warnings writer: reopen %s: %w", w.path, err)
	}
	w.file = f
	return nil
}

// Close closes the underlying file. Safe to call multiple times — second call is a no-op.
//
// Called from: graceful shutdown (main.go).
// Blocking: write lock.
func (w *WarningsWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file == nil {
		return nil
	}
	_ = w.file.Sync()
	err := w.file.Close()
	w.file = nil
	return err
}

// ========================== Line formatting ===========================================

// formatChainWarningLine produces one CHAIN_WARN log line.
// kind "cloudflare" → label "cloudflare-ip-as-client"
// kind "bogon"      → label "bogon-ip-as-client"
// Unknown kinds fall back to "<kind>-ip-as-client" to stay forward-compatible.
func formatChainWarningLine(result *chaincheck.CheckResult, logFile string) string {
	timestamp := time.Now().UTC().Format(time.RFC3339)
	label := result.Kind + "-ip-as-client"
	return fmt.Sprintf("%s CHAIN_WARN %s ip=%s cidr=%s log=%s",
		timestamp, label, result.IP, result.MatchedCIDR, logFile)
}
