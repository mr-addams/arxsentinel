// ========================== Module arx-core/pkg/tail ==========================================
//   Tail-reader for reading access.log in tail -f mode with logrotate support.
//   Uses fsnotify (inotify) to detect file rotation.
//
//   WHAT IS HERE:
//     - TailReader — reads from EOF position, delivers new lines through a channel
//     - Handling logrotate mv method: RENAME → wait for CREATE → reopen
//     - Handling copytruncate: detect pos > size → seek(0)
//
//   WHAT IS NOT HERE:
//     - Line parsing (core/parser)
//     - Business logic (core/)
//
//   ARCHITECTURE (Run):
//     Start      → waitForFile (seek EOF) → watcher(dir + file)
//     WRITE      → [copytruncate?] → readAvailableLines
//     RENAME/RM  → drain tail → close → f = nil
//     CREATE     → open new file → read from start
//   ctx.Done() → close fd → return

// Package tail implements a tail-following reader with logrotate support.
//
// Decoupled from a concrete logger: the consumer injects a logFn callback
// (same pattern as arx-core/pkg/source/file.FileSource). nil is replaced
// with an internal no-op so call-sites can pass nil safely.
package tail

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
)

// noopLogFn is the default no-op sink for NewTailReader when logFn is nil.
// Kept package-private; callers should pass their own callback when they
// want observability.
func noopLogFn(tag, msg, level string) {}

// maxLineSize — maximum accepted line length in bytes.
// ReadString accumulates chunks until '\n' — an anomalously long URL in the nginx log
// could force a large one-shot allocation. Lines exceeding this limit are dropped.
const maxLineSize = 64 * 1024 // 64 KB — well above any real access.log line

// readLineTimeout — максимальное время ожидания одной строки из файла
// (L2). Если файл — pipe или NFS, ReadString может заблокироваться
// бесконечно. Таймаут переводит читающую горутину в фоновый режим
// (данные теряются) и освобождает основной цикл.
const readLineTimeout = 30 * time.Second

// ========================== TailReader ================================================

// TailReader reads a file in tail -f mode, sending new lines to the lines channel.
// Supports two logrotate methods:
//   - mv + postrotate (RENAME): file is renamed, nginx creates a new one
//   - copytruncate: file is truncated in place, position moves past the new EOF
//
// Lifecycle of the variable f inside Run:
//
//	opened at EOF  → reads WRITE events  → closed on RENAME
//	nil            → waiting for new file after rotation (f == nil is normal)
//	reopened       → after CREATE of the new file
//
// Internal — tracks current file descriptor. Consumer: Run
type TailReader struct {
	filePath      string        // YAML: inputs[i].path — path to the log file. Consumer: Run
	lines         chan string   // YAML: — buffered channel for read lines. Consumer: pipeline.runSource
	retryInterval time.Duration // YAML: general.tail_retry_interval, default 1s — retry interval when file is unavailable. Consumer: waitForFile
	logFn         func(tag, msg, level string)
}

// NewTailReader creates a TailReader.
// lines — buffered channel for read lines (size: cfg.General.LinesBufSize).
// retryInterval — wait interval when file is unavailable (cfg.General.TailRetryInterval).
// logFn — injected logger callback; nil is replaced with a no-op.
// TailReader closes the channel when Run completes — main can wait for !ok during drain.
// Called from: pipeline.runSource.
// Start with: go t.Run(ctx). Blocking.
func NewTailReader(filePath string, lines chan string, retryInterval time.Duration, logFn func(tag, msg, level string)) *TailReader {
	lf := logFn
	if lf == nil {
		lf = noopLogFn
	}
	return &TailReader{
		filePath:      filePath,
		lines:         lines,
		retryInterval: retryInterval,
		logFn:         lf,
	}
}

// Run — blocking read loop. Call with: go t.Run(ctx).
// Stops on ctx.Done().
// At startup opens the file and seeks to EOF — we only read new lines,
// not the entire historical log (which may be huge and already processed).
//
// Called from: pipeline.runSource (go t.Run(ctx)).
// Blocking — runs until ctx cancellation or watcher error.
func (t *TailReader) Run(ctx context.Context) {
	// Closing the channel signals main that TailReader has finished writing —
	// the drain loop in main can correctly wait for !ok instead of racing on default.
	defer close(t.lines)

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		t.logFn("TAIL", fmt.Sprintf("failed to create watcher: %v", err), "error")
		return
	}
	defer watcher.Close()

	// Watch the directory to detect CREATE (new file after mv rotation).
	// Only the directory guarantees receiving CREATE after the old inode disappears.
	dir := filepath.Dir(t.filePath)
	if err := watcher.Add(dir); err != nil {
		t.logFn("TAIL", fmt.Sprintf("failed to watch directory %s: %v", dir, err), "error")
		return
	}

	// Open the file; if it does not exist yet — wait for it to appear
	f := t.waitForFile(ctx)
	if f == nil {
		// ctx was cancelled while waiting for the file
		return
	}
	// M5: safety net — закрываем fd при любом нештатном выходе из цикла
	defer func() {
		if f != nil {
			f.Close()
		}
	}()

	// Watch the file itself for WRITE/RENAME/REMOVE events.
	// Not fatal if Add fails — WRITE events will still arrive via directory watch.
	if err := watcher.Add(t.filePath); err != nil {
		t.logFn("TAIL", fmt.Sprintf("failed to watch file %s: %v", t.filePath, err), "error")
	}

	reader := bufio.NewReaderSize(f, maxLineSize)

	t.logFn("TAIL", fmt.Sprintf("watching started: %s", t.filePath), "info")

	for {
		select {
		case <-ctx.Done():
			t.logFn("TAIL", "watching stopped", "info")
			if f != nil {
				f.Close()
				f = nil
			}
			return

		case event, ok := <-watcher.Events:
			if !ok {
				if f != nil {
					f.Close()
					f = nil
				}
				return
			}
			t.logFn("TAIL", fmt.Sprintf("fsnotify: %s %s", event.Op, event.Name), "debug")

			switch {
			case t.isTargetFile(event) && event.Has(fsnotify.Write):
				// New data — first check for truncation (copytruncate logrotate),
				// then read lines.
				if f != nil && t.handleTruncation(f, reader) {
					t.logFn("TAIL", "copytruncate: file truncated, reading from start", "info")
				}
				if f != nil {
					t.readAvailableLines(reader)
				}

			case t.isTargetFile(event) && (event.Has(fsnotify.Rename) || event.Has(fsnotify.Remove)):
				// File renamed/removed (mv logrotate method).
				// Drain the tail from the old fd — nginx may have written lines between
				// the last WRITE event and the rename.
				if f != nil {
					t.readAvailableLines(reader)
					f.Close()
					f = nil
				}
				_ = watcher.Remove(t.filePath) // inode gone — remove watch
				t.logFn("TAIL", "file rotated (mv), waiting for new file", "info")

			case t.isTargetFile(event) && event.Has(fsnotify.Create):
				// New file created (after mv rotation or nginx recreation).
				// f == nil during normal mv rotation (RENAME closed it above) — this is expected.
				// Open from the start of the file — these are the first records of the new log.
				if f != nil {
					f.Close()
					f = nil
				}
				newF, err := os.Open(t.filePath)
				if err != nil {
					t.logFn("TAIL", fmt.Sprintf("failed to open new file: %v", err), "error")
					f = nil
					continue
				}
				f = newF
				reader.Reset(f)
				_ = watcher.Add(t.filePath)
				t.logFn("TAIL", "new file opened after rotation", "info")
				t.readAvailableLines(reader)
			}

		case err, ok := <-watcher.Errors:
			if !ok {
				if f != nil {
					f.Close()
					f = nil
				}
				return
			}
			t.logFn("TAIL", fmt.Sprintf("watcher error: %v", err), "error")
		}
	}
}

// ========================== Helper methods ============================================

// waitForFile waits for the file to appear and opens it at EOF position.
// Returns nil if ctx is cancelled before the file appears.
// Seek(EOF) at startup — the historical log may be huge; we don't read it.
//
// time.NewTimer(0) + Reset: reuses one timer instead of time.After,
// which creates a new *time.Timer on each iteration and does not release it
// until it fires — on a long wait for the file, timers accumulate.
//
// Called from: Run. Non-blocking (timer-driven, yields to ctx).
func (t *TailReader) waitForFile(ctx context.Context) *os.File {
	timer := time.NewTimer(0) // first iteration fires immediately, no delay
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
			f, err := os.Open(t.filePath)
			if err == nil {
				if _, seekErr := f.Seek(0, io.SeekEnd); seekErr != nil {
					f.Close()
					t.logFn("TAIL", fmt.Sprintf("seek(EOF) error in %s: %v", t.filePath, seekErr), "error")
				} else {
					return f
				}
			} else {
				t.logFn("TAIL", fmt.Sprintf("file unavailable (%v), retrying in %v", err, t.retryInterval), "warning")
			}
			timer.Reset(t.retryInterval)
		}
	}
}

// handleTruncation detects file truncation (logrotate copytruncate) and
// resets the read position to the beginning of the file.
// Returns true if truncation was detected and seek(0) was performed.
//
// Called from: Run (WRITE event handling). Non-blocking.
func (t *TailReader) handleTruncation(f *os.File, reader *bufio.Reader) bool {
	pos, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	if pos > info.Size() {
		// Current position is past the new file size — file was truncated in place
		_, _ = f.Seek(0, io.SeekStart)
		reader.Reset(f)
		return true
	}
	return false
}

// readResult carries the outcome of a single ReadString call.
type readResult struct {
	line string
	err  error
}

// readLineWithTimeout вызывает reader.ReadString('\n') с таймаутом.
// Если таймаут сработал, возвращает ("", nil) — строка теряется.
// При таймауте фоновая горутина продолжает читать и выбрасывает результат;
// это приемлемо: таймауты редки (pipe/NFS edge cases), и горутина
// завершается при первой же доставке данных от OS.
func readLineWithTimeout(reader *bufio.Reader, timeout time.Duration) (string, error) {
	ch := make(chan readResult, 1)
	go func() {
		line, err := reader.ReadString('\n')
		ch <- readResult{line, err}
	}()
	select {
	case res := <-ch:
		return res.line, res.err
	case <-time.After(timeout):
		return "", nil
	}
}

// readAvailableLines reads all available lines up to io.EOF and sends them to the channel.
// Non-blocking — stops at io.EOF (no more data at this moment).
// On channel overflow the line is dropped — better to lose a line than to
// block the watcher loop and miss rotation events.
//
// Called from: Run (WRITE, CREATE, RENAME event handling). Non-blocking.
func (t *TailReader) readAvailableLines(reader *bufio.Reader) {
	for {
		line, err := readLineWithTimeout(reader, readLineTimeout) // L2: таймаут на ReadString
		if len(line) > 0 {
			// Drop anomalously long lines before trimming — an oversized URL
			// in the log is either corruption or an overflow attack; skip it.
			if len(line) > maxLineSize {
				t.logFn("TAIL", fmt.Sprintf("line too long (%d bytes), dropped", len(line)), "warning")
				if err != nil {
					return
				}
				continue
			}
			line = strings.TrimRight(line, "\r\n")
			if line != "" {
				select {
				case t.lines <- line:
				default:
					// Downstream (parser/processor) is too slow — line dropped
					t.logFn("TAIL", "channel full, line dropped", "warning")
				}
			}
		}
		if err != nil {
			// io.EOF — normal, waiting for the next WRITE event
			return
		}
	}
}

// isTargetFile checks that the fsnotify event concerns the watched file.
// fsnotify may return an absolute path even if Add received a relative one —
// filepath.Clean normalizes both paths before comparison.
func (t *TailReader) isTargetFile(event fsnotify.Event) bool {
	return filepath.Clean(event.Name) == filepath.Clean(t.filePath)
}
