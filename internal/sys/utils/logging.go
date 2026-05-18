// ========================== Module utils/logging ========================================
//   Three logging streams: console (colored stdout), operational (sentinel.log),
//   threat (threats.log). Tagged output following patterns from the telegram-bot logging.go.
//
//   WHAT IS HERE:
//     - Init() — initializes file loggers
//     - Log(tag, msg, level) — console + sentinel.log
//     - LogThreat() — writes to threats.log (format for Fail2Ban)
//     - Close() — closes file descriptors
//
//   WHAT IS NOT HERE:
//     - Business logic (core/)
//     - Configuration structures (sys/config)
//
//   OUTER TAGS: STARTUP, SHUTDOWN, CONFIG, PARSER, DETECTOR, SCORER,
//               WHITELIST, THREAT, STATS, GC, TAIL, ERROR, WARN, INFO, DEBUG
//   INNER TAGS: PROBE, RATE, UA, BRUTEFORCE, CRAWLER, NOASSET,
//               OVERFLOW, DNS, GC
//
//   FILTERING:
//     debugOnlyTags — visible only when DebugEnabled=true
//     quietTags     — show only error/warning without debug mode

package utils

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
)

// ========================== Global state ===============================================
//
// logMu protects operationalWriter and threatWriter from concurrent access during SIGHUP reload:
// the GC goroutine calls Log/LogThreat in parallel with Reload() in the main goroutine.
// Readers (Log, LogThreat) acquire RLock; Reload acquires Lock for descriptor swap.

var (
	// debugEnabled / colorEnabled — atomics: read from Log without a lock (fast path),
	// updated in Init/Reload from the main goroutine.
	debugEnabled atomic.Bool
	colorEnabled atomic.Bool

	// logMu protects operationalWriter and threatWriter.
	logMu sync.RWMutex

	// operationalWriter — file descriptor for sentinel.log.
	// nil if the file could not be opened — we continue with console only.
	operationalWriter *os.File

	// threatWriter — file descriptor for threats.log.
	// nil if the file could not be opened — Init returns an error.
	threatWriter *os.File
)

func init() {
	colorEnabled.Store(true) // colors enabled by default before explicit Init
}

// ========================== Color initialization =======================================

// Color variables — private, used only within the package.
// core/ does not import sys/utils directly, so no export is needed.
var (
	timestampColor = color.New(color.FgBlue)
	blueColor      = color.New(color.FgBlue)
	redColor       = color.New(color.FgRed)
	yellowColor    = color.New(color.FgYellow)
	magentaColor   = color.New(color.FgMagenta)
	cyanColor      = color.New(color.FgCyan)
	greenColor     = color.New(color.FgGreen)
	orangeColor    = color.New(color.FgHiRed)
)

// logColors — colors for outer tags.
// Semantics: green = success/startup, red = threat/error, yellow = warning,
// cyan = informational, magenta = configuration.
var logColors = map[string]*color.Color{
	"STARTUP":   greenColor,
	"SHUTDOWN":  redColor,
	"CONFIG":    magentaColor,
	"PARSER":    cyanColor,
	"DETECTOR":  yellowColor,
	"SCORER":    cyanColor,
	"WHITELIST": magentaColor,
	"THREAT":    redColor,
	"STATS":     greenColor,
	"GC":        cyanColor,
	"TAIL":      cyanColor,
	"ERROR":     redColor,
	"WARN":      yellowColor,
	"INFO":      cyanColor,
	"DEBUG":     orangeColor,
}

// innerTagColors — colors for inner tags of the form [PROBE] inside the message body.
var innerTagColors = map[string]*color.Color{
	"PROBE":      yellowColor,
	"RATE":       orangeColor,
	"UA":         magentaColor,
	"BRUTEFORCE": orangeColor,
	"CRAWLER":    yellowColor,
	"NOASSET":    cyanColor,
	"OVERFLOW":   redColor,
	"DNS":        blueColor,
	"GC":         cyanColor,
}

// debugOnlyTags — tags visible only when DebugEnabled=true.
// PARSER and TAIL are suppressed in production — they emit one line per nginx log entry.
var debugOnlyTags = map[string]bool{
	"DEBUG":  true,
	"PARSER": true, // one line per nginx entry — too noisy in production
	"TAIL":   true, // inotify filesystem events — debug noise
}

// quietTags — tags that show only error/warning without debug mode.
// Detectors and Scorer emit many messages during processing — only needed
// during debugging, not in routine monitoring.
var quietTags = map[string]bool{
	"DETECTOR": true,
	"SCORER":   true,
}

// ========================== Initialization ============================================

// Init opens file descriptors for operational and threat logs.
// Creates directories if they do not exist.
//
// Error behavior:
//   - Operational log unavailable → warning to stderr, continue (console works).
//   - Threat log unavailable → return error: Fail2Ban cannot work without it.
//
// Called from main.go once at startup.
func Init(debug, consoleColor bool, operationalLogPath, threatLogPath string) error {
	debugEnabled.Store(debug)
	colorEnabled.Store(consoleColor)

	// Operational log — non-critical, only warn on unavailability
	if err := ensureDir(operationalLogPath); err != nil {
		fmt.Fprintf(os.Stderr, "[WARN] failed to create directory for operational log: %v\n", err)
	} else {
		f, err := os.OpenFile(operationalLogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[WARN] operational log unavailable (%s): %v — continuing with console only\n", operationalLogPath, err)
		} else {
			operationalWriter = f
		}
	}

	// Threat log — skipped in multi-stream mode (each stream manages its own file).
	// When non-empty, it is critical: Fail2Ban cannot receive data without it.
	if threatLogPath != "" {
		if err := ensureDir(threatLogPath); err != nil {
			return fmt.Errorf("threat log directory: %w", err)
		}
		tf, err := os.OpenFile(threatLogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return fmt.Errorf("threat log unavailable (%s): %w", threatLogPath, err)
		}
		threatWriter = tf
	}

	return nil
}

// Reload atomically swaps file descriptors and flags after SIGHUP.
// Opens new files before acquiring the lock, then atomically swaps the pointers
// and closes the old descriptors outside the lock (readers no longer see old).
//
// Error semantics: operational log is non-critical (warn + nil writer);
// threat log is critical — on error returns error without changing state.
func Reload(debug, consoleColor bool, operationalLogPath, threatLogPath string) error {
	// Open new descriptors before the lock — IO does not hold the mutex
	var newOperWriter *os.File
	if err := ensureDir(operationalLogPath); err != nil {
		fmt.Fprintf(os.Stderr, "[WARN] Reload: failed to create operational log directory: %v\n", err)
	} else if f, err := os.OpenFile(operationalLogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644); err == nil {
		newOperWriter = f
	} else {
		fmt.Fprintf(os.Stderr, "[WARN] Reload: operational log unavailable: %v\n", err)
	}

	var newThreatWriter *os.File
	if threatLogPath != "" {
		if err := ensureDir(threatLogPath); err != nil {
			if newOperWriter != nil {
				newOperWriter.Close()
			}
			return fmt.Errorf("Reload: threat log directory: %w", err)
		}
		tf, err := os.OpenFile(threatLogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			if newOperWriter != nil {
				newOperWriter.Close()
			}
			return fmt.Errorf("Reload: threat log unavailable (%s): %w", threatLogPath, err)
		}
		newThreatWriter = tf
	}

	// Update flags only after files are successfully opened —
	// on error above state stays consistent (atomics = descriptors = old config).
	debugEnabled.Store(debug)
	colorEnabled.Store(consoleColor)

	// Atomic swap under write lock — readers are blocked for the minimum time
	logMu.Lock()
	oldOper, oldThreat := operationalWriter, threatWriter
	operationalWriter = newOperWriter
	threatWriter = newThreatWriter
	logMu.Unlock()

	// Close old descriptors outside the lock — readers already see the new ones
	if oldOper != nil {
		_ = oldOper.Sync()
		_ = oldOper.Close()
	}
	if oldThreat != nil {
		_ = oldThreat.Sync()
		_ = oldThreat.Close()
	}

	return nil
}

// Close flushes OS buffers and closes file descriptors. Call via defer in main.go.
// Sync() before Close() ensures the last writes are not lost on SIGTERM — the kernel
// may hold data in page cache without fsync until an explicit call.
func Close() {
	logMu.Lock()
	ow, tw := operationalWriter, threatWriter
	operationalWriter = nil
	threatWriter = nil
	logMu.Unlock()

	if ow != nil {
		_ = ow.Sync()
		_ = ow.Close()
	}
	if tw != nil {
		_ = tw.Sync()
		_ = tw.Close()
	}
}

// ensureDir creates the directory for the given file path if it does not exist.
func ensureDir(filePath string) error {
	dir := filepath.Dir(filePath)
	return os.MkdirAll(dir, 0755)
}

// ========================== Main logging ==============================================

// Log — colored console log with tag and timestamp + write to sentinel.log.
//
// tag: outer tag (STARTUP, CONFIG, THREAT, etc.)
// level: "info" | "warning" | "error" | "debug"
//
// Filtering:
//   - debugOnlyTags: suppressed in production (DebugEnabled=false)
//   - quietTags: shown only on error/warning or DebugEnabled=true
//
// If the body starts with [TAG] — the inner tag is colorized separately.
func Log(tag, message, level string) {
	// debugOnlyTags: only shown when debug mode is explicitly enabled
	if debugOnlyTags[tag] && !debugEnabled.Load() {
		return
	}
	// quietTags: in production show only significant events
	if quietTags[tag] && !debugEnabled.Load() {
		if level != "error" && level != "warning" {
			return
		}
	}

	timestamp := time.Now().Format("2006-01-02 15:04:05")

	// ── Write to sentinel.log (plain text, no ANSI) ───────────────────────────────────
	// Write to file before color formatting — avoids ANSI codes in the file.
	// RLock guards against descriptor swap during SIGHUP reload.
	logMu.RLock()
	if operationalWriter != nil {
		fmt.Fprintf(operationalWriter, "%s [%s] %s\n", timestamp, tag, message)
	}
	logMu.RUnlock()

	// ── Console formatting ────────────────────────────────────────────────────────────

	tagColor, ok := logColors[tag]
	if !ok {
		tagColor = color.New(color.Reset)
	}

	// Extract inner tag of the form [PROBE] from the start of the message body.
	// len > 2: minimum length of [X] = 3 chars — ensures there is something to parse.
	innerName := ""
	innerTagStr := ""
	body := message
	if len(message) > 2 && message[0] == '[' {
		if end := strings.Index(message, "] "); end > 0 {
			name := message[1:end]
			if c, found := innerTagColors[name]; found {
				innerName = name
				innerTagStr = c.Sprintf("[%s]", name) // used only when ColorEnabled
				body = message[end+2:]
			}
		}
	}

	var line string
	if colorEnabled.Load() {
		ts := timestampColor.Sprint(timestamp)
		t := tagColor.Sprintf("[%s]", tag)
		if innerTagStr != "" {
			line = fmt.Sprintf("%s %s %s %s", ts, t, innerTagStr, body)
		} else {
			line = fmt.Sprintf("%s %s %s", ts, t, body)
		}
	} else {
		// plain text — innerName was extracted above, no repeated strings.Index needed
		if innerName != "" {
			line = fmt.Sprintf("%s [%s] [%s] %s", timestamp, tag, innerName, body)
		} else {
			line = fmt.Sprintf("%s [%s] %s", timestamp, tag, message)
		}
	}

	fmt.Println(line)
}

// ========================== Threat log ================================================

// LogThreat writes a threat event to threats.log (format for Fail2Ban).
// Also mirrors the record to console with tag THREAT.
//
// threatLevel: "WARN" (score 50–79) or "THREAT" (score 80+)
// modules: list of triggered detectors (["probe", "rate", "useragent"])
// reason: details per module ("env_probe:3,rate:142rps,ua:Nuclei")
//
// Line format:
//
//	2026-04-02T14:33:12Z THREAT 45.134.26.8 score=85 modules=probe,rate reason="..."
func LogThreat(ip string, score int, threatLevel string, modules []string, reason string) {
	// RFC3339 — standard for machine-readable timestamps; compatible with Fail2Ban
	timestamp := time.Now().UTC().Format(time.RFC3339)
	modulesStr := strings.Join(modules, ",")

	line := fmt.Sprintf("%s %s %s score=%d modules=%s reason=%q",
		timestamp, threatLevel, ip, score, modulesStr, reason)

	// Write to threats.log — this is the file Fail2Ban reads.
	// RLock guards against descriptor swap during SIGHUP reload.
	// nil means Init was not called or Close() was called — signal explicitly,
	// otherwise the threat is silently lost and Fail2Ban is blind to the attack.
	logMu.RLock()
	if threatWriter == nil {
		logMu.RUnlock()
		Log("ERROR", fmt.Sprintf("[THREAT] threatWriter=nil, threat lost: %s score=%d modules=%s", ip, score, modulesStr), "error")
	} else {
		_, err := fmt.Fprintln(threatWriter, line)
		logMu.RUnlock()
		// Write error (disk full, fd invalidation) is logged directly to stderr —
		// recursion through Log/logMu is not possible; Fail2Ban must know about the lost record.
		if err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] threat record lost (%s score=%d): %v\n", ip, score, err)
		}
	}

	// Mirror to console as [THREAT] for real-time monitoring
	Log("THREAT", fmt.Sprintf("%s score=%d modules=%s reason=%q", ip, score, modulesStr, reason), "warning")
}

// ========================== Per-stream threat log helpers =============================

// OpenThreatLog opens (or creates) a threat log file for a single stream.
// Used by runStream() in multi-stream mode — each stream owns its file descriptor.
func OpenThreatLog(path string) (*os.File, error) {
	if path == "" {
		return nil, fmt.Errorf("threat log path is empty")
	}
	if err := ensureDir(path); err != nil {
		return nil, fmt.Errorf("threat log directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("threat log unavailable (%s): %w", path, err)
	}
	return f, nil
}
