// ========================== Package nginx ==========================
//   NginxExecutor — manages an IP blocklist file for nginx: writes banned
//   IPs as "<ip> 1;" entries, supports TTL-based auto-sweep, dedup,
//   and optional nginx reload via external command.
//
//   WHAT IS HERE:
//     - NginxExecutor struct with Run loop, flush, sweep, syncExisting
//     - Atomic file write via .tmp + os.Rename
//     - Optional JSON state file for TTL persistence across restarts
//
//   WHAT IS NOT HERE:
//     - Configuration parsing (see config.go)
//     - Registration (see register.go)
//
//   Gate B (Flow 083 / Task 3.3 / RESOLVED-D): ThreatEvent lives in the
//   product namespace cmd/arxsentinel/internal/threat; the executor
//   type-asserts Event.Payload to *threat.ThreatEvent.

package nginx

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mr-addams/arx-core/pkg/executor"
	"github.com/mr-addams/arx-core/pkg/logger"
	"github.com/mr-addams/arx-core/pkg/plugin"

	"github.com/mr-addams/arxsentinel/internal/threat"
)

const (
	defaultSweepInterval = 15 * time.Minute
	maxSweepInterval     = 30 * time.Minute
)

// fileHeader is prepended to every written list file to warn manual editors.
const fileHeader = "# managed by arxsentinel — do not edit manually\n"

// ++++++++++++++++++++++++++ Executor struct +++++++++++++++++++++++++++++++++

// NginxExecutor manages an IP blocklist file for nginx.
// It receives ThreatEvents, deduplicates by IP, writes to a list file,
// and optionally calls a reload command after each write.
type NginxExecutor struct {
	name     string
	execType string
	cfg      Config

	// logger is the operational logger injected by the caller. Replaces the
	// pre-1.2 global utils.Log dependency — see Flow 072 Decision 2. Always
	// non-nil in practice (constructor replaces nil with logger.Nop).
	logger logger.Logger

	mu     sync.RWMutex
	banned map[string]time.Time

	stats struct {
		executed atomic.Int64
		skipped  atomic.Int64
		errors   atomic.Int64
	}
}

// ++++++++++++++++++++++++++ Constructor +++++++++++++++++++++++++++++++++++++

// NewNginxExecutor creates a new NginxExecutor from a generic
// executor.ExecutorConfig (Flow 073 / Task 1.3.1 — was config.ExecutorItem
// pre-1.3.1). The raw cfg.Config map is forwarded to parseConfig() which
// validates the implementation-specific block; only cfg.Name is consumed
// at this layer (used in the WARNING below and as the executor identity).
//
// `log` is the operational logger injected by the registry factory. The
// pre-1.3.1 wiring passed logger.Nop here, which silently swallowed
// EXECUTOR-tag diagnostics — this is the F1 closure point in Nginx.
//
// It parses the config, logs a WARNING if ReloadCmd is empty, and
// initialises the banned map.
func NewNginxExecutor(cfg executor.ExecutorConfig, log logger.Logger) (plugin.Executor, error) {
	// Inject the operational logger. nil is replaced with logger.Nop so
	// downstream code (including the WARNING below) never has to nil-check.
	// See Flow 072 Decision 2.
	if log == nil {
		log = logger.Nop
	}

	parsed, err := parseConfig(cfg.Config)
	if err != nil {
		return nil, fmt.Errorf("nginx: new executor: %w", err)
	}

	if parsed.TTL <= 0 {
		return nil, fmt.Errorf("nginx: new executor: TTL must be positive, got %v", parsed.TTL)
	}

	if parsed.ReloadCmd == "" {
		log.Log("EXECUTOR", fmt.Sprintf("nginx executor %q: reload_cmd is empty — bans are written but nginx will not be reloaded automatically", cfg.Name), logger.LevelWarning)
	}

	return &NginxExecutor{
		name:     cfg.Name,
		execType: "nginx",
		cfg:      parsed,
		banned:   make(map[string]time.Time),
		logger:   log,
	}, nil
}

// ++++++++++++++++++++++++++ Interface methods +++++++++++++++++++++++++++++++

func (e *NginxExecutor) Name() string {
	return e.name
}

func (e *NginxExecutor) Type() string {
	return e.execType
}

// ++++++++++++++++++++++++++ File I/O helpers ++++++++++++++++++++++++++++++++

// writeFile atomically writes data to path using a .tmp intermediate file.
// Opens the .tmp file, writes data, calls Sync() (H4), then renames to path.
// Sync() guarantees the data is on disk before the atomic rename — without it,
// a crash after rename but before sync could leave an empty file for nginx.
func writeFile(path, data string) error {
	dir := filepath.Dir(path)
	tmpPath := path + ".tmp"
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("writeFile: mkdir: %w", err)
	}

	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("writeFile: create tmp: %w", err)
	}

	if _, err := f.WriteString(data); err != nil {
		f.Close()
		return fmt.Errorf("writeFile: write tmp: %w", err)
	}

	// H4: fsync перед rename — гарантия, что данные на диске.
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("writeFile: sync tmp: %w", err)
	}

	if err := f.Close(); err != nil {
		return fmt.Errorf("writeFile: close tmp: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("writeFile: rename: %w", err)
	}
	return nil
}

// saveState writes the banned map as a JSON file at StateFile (if configured).
// Format: {"ip": "2026-06-01T12:00:00Z", ...}.
// M6: timestamps are serialized as RFC3339 UTC; timezone is not preserved —
// all times are stored and restored as UTC to avoid DST/timezone ambiguity.
func (e *NginxExecutor) saveState(banned map[string]time.Time) {
	if e.cfg.StateFile == "" {
		return
	}
	data, err := json.Marshal(banned)
	if err != nil {
		e.stats.errors.Add(1)
		e.logger.Log("EXECUTOR", fmt.Sprintf("nginx executor %q: saveState marshal: %v", e.name, err), logger.LevelError)
		return
	}
	if err := writeFile(e.cfg.StateFile, string(data)); err != nil {
		e.stats.errors.Add(1)
		e.logger.Log("EXECUTOR", fmt.Sprintf("nginx executor %q: saveState write: %v", e.name, err), logger.LevelError)
	}
}

// ++++++++++++++++++++++++++ Startup sync ++++++++++++++++++++++++++++++++++++

// syncExisting reads the current list_file to populate the banned map,
// and optionally reads the state_file to recover TTL timestamps.
//
// If a state_file exists and is valid JSON, its timestamps are used as addedAt.
// IPs present in the list_file but missing from the state_file get addedAt = now.
// A corrupted state_file is ignored with a WARNING — behaviour degrades to
// no-state-file mode (all IPs get addedAt = now).
func (e *NginxExecutor) syncExisting() {
	e.mu.Lock()
	defer e.mu.Unlock()

	// ---- Load state file for TTL timestamps (optional, best-effort) ----
	stateMap := make(map[string]time.Time)
	if e.cfg.StateFile != "" {
		data, err := os.ReadFile(e.cfg.StateFile)
		if err == nil {
			if err := json.Unmarshal(data, &stateMap); err != nil {
				e.logger.Log("EXECUTOR", fmt.Sprintf("nginx executor %q: state file %q is corrupted (invalid JSON) — ignoring, TTL will be calculated from now", e.name, e.cfg.StateFile), logger.LevelWarning)
				stateMap = make(map[string]time.Time)
			}
		}
		// File not found on first run is not an error — no existing state.
	}

	// ---- Parse list_file ----
	f, err := os.Open(e.cfg.ListFile)
	if err != nil {
		// File not found on first run — executor starts with empty banned map.
		return
	}
	defer f.Close()

	now := time.Now()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasSuffix(line, "1;") {
			continue
		}
		ip := strings.TrimSuffix(line, " 1;")
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		addedAt, ok := stateMap[ip]
		if !ok {
			addedAt = now
		}
		e.banned[ip] = addedAt
	}
	if err := scanner.Err(); err != nil {
		e.logger.Log("EXECUTOR", fmt.Sprintf("nginx executor %q: syncExisting: read error: %v — banned map may be incomplete", e.name, err), logger.LevelWarning)
	}
}

// ++++++++++++++++++++++++++ Reload command ++++++++++++++++++++++++++++++++++

// runReload executes the reload command if one is configured.
// Uses exec.CommandContext with the configured ReloadTimeout for cancellation.
// Logs CombinedOutput on error.
func (e *NginxExecutor) runReload(ctx context.Context) {
	if e.cfg.ReloadCmd == "" {
		return
	}

	execCtx, cancel := context.WithTimeout(ctx, e.cfg.ReloadTimeout)
	defer cancel()

	cmd := exec.CommandContext(execCtx, "sh", "-c", e.cfg.ReloadCmd)
	output, err := cmd.CombinedOutput()
	if err != nil {
		e.stats.errors.Add(1)
		e.logger.Log("EXECUTOR", fmt.Sprintf("nginx executor %q: reload failed: %v — output: %s", e.name, err, strings.TrimSpace(string(output))), logger.LevelError)
		return
	}
	if len(output) > 0 {
		e.logger.Log("EXECUTOR", fmt.Sprintf("nginx executor %q: reload output: %s", e.name, strings.TrimSpace(string(output))), logger.LevelInfo)
	}
}

// ++++++++++++++++++++++++++ Flush +++++++++++++++++++++++++++++++++++++++++++

// flush writes all currently banned IPs to the list file, saves state,
// and calls the reload command.
//
// The data format is:
//
//	<ip> 1;
//
// With a header line: "# managed by arxsentinel — do not edit manually\n"
func (e *NginxExecutor) flush(ctx context.Context, banned map[string]time.Time) {
	// L4: проверка отмены контекста перед началом flush — не начинаем запись
	// если pipeline уже завершается. Избегаем лишней IO и reload при shutdown.
	select {
	case <-ctx.Done():
		return
	default:
	}

	if len(banned) == 0 {
		return
	}

	var sb strings.Builder
	sb.WriteString(fileHeader)
	for ip := range banned {
		sb.WriteString(ip)
		sb.WriteString(" 1;\n")
	}

	if err := writeFile(e.cfg.ListFile, sb.String()); err != nil {
		e.stats.errors.Add(1)
		e.logger.Log("EXECUTOR", fmt.Sprintf("nginx executor %q: flush write: %v", e.name, err), logger.LevelError)
		return
	}

	e.saveState(banned)
	e.runReload(ctx)
	e.stats.executed.Add(int64(len(banned)))
}

// ++++++++++++++++++++++++++ Sweep +++++++++++++++++++++++++++++++++++++++++++

// sweep removes expired IPs from the banned map and rewrites the list file.
// An IP expires when time.Since(addedAt) > cfg.TTL.
// If no IPs expired, returns early without writing or reloading.
func (e *NginxExecutor) sweep(ctx context.Context) {
	e.mu.Lock()
	now := time.Now()
	changed := false
	for ip, addedAt := range e.banned {
		if now.Sub(addedAt) > e.cfg.TTL {
			delete(e.banned, ip)
			changed = true
		}
	}
	if !changed {
		e.mu.Unlock()
		return
	}
	// Snapshot the current banned map for flush while holding the lock.
	// Even if len(e.banned) == 0, still write the file to clear all bans.
	bannedSnapshot := make(map[string]time.Time, len(e.banned))
	for ip, addedAt := range e.banned {
		bannedSnapshot[ip] = addedAt
	}
	e.mu.Unlock()

	e.flush(ctx, bannedSnapshot)
}

// ++++++++++++++++++++++++++ Run loop ++++++++++++++++++++++++++++++++++++++++

// Run reads ThreatEvents from source, accumulates them, and flushes to the
// list file when batch_size is reached or flush_interval fires.
// Also runs periodic sweep to remove expired bans.
func (e *NginxExecutor) Run(ctx context.Context, source plugin.EventSource) error {
	// ---- Startup sync ----
	e.syncExisting()

	tickerFlush := time.NewTicker(e.cfg.FlushInterval)
	defer tickerFlush.Stop()

	sweepInterval := e.cfg.TTL / 4
	if sweepInterval < defaultSweepInterval {
		sweepInterval = defaultSweepInterval
	}
	if sweepInterval > maxSweepInterval {
		sweepInterval = maxSweepInterval
	}
	tickerSweep := time.NewTicker(sweepInterval)
	defer tickerSweep.Stop()

	// Internal channel for events — Pop is not channel-based.
	// Gate B (Flow 083 / Task 3.3): Pop returns generic *plugin.Event;
	// we extract the *threat.ThreatEvent payload and forward ThreatEvent
	// values down the same batch path. A wrong payload type is a programmer
	// error and is dropped here.
	events := make(chan threat.ThreatEvent, e.cfg.BatchSize)
	go func() {
		defer close(events)
		for {
			ev, err := source.Pop(ctx)
			if err != nil {
				return
			}
			te, ok := ev.Payload.(*threat.ThreatEvent)
			if !ok {
				fmt.Fprintf(os.Stderr, "[nginx executor] skipped non-ThreatEvent payload: %T\n", ev.Payload)
				continue
			}
			select {
			case events <- *te:
			case <-ctx.Done():
				return
			}
		}
	}()

	buffer := make([]threat.ThreatEvent, 0, e.cfg.BatchSize)

	for {
		select {
		case <-ctx.Done():
			e.flushLocked(ctx)
			e.sweep(ctx)
			return ctx.Err()
		case event, ok := <-events:
			if !ok {
				e.flushLocked(ctx)
				e.sweep(ctx)
				return nil
			}
			if !e.meetsMinLevel(event.Level) {
				e.stats.skipped.Add(1)
				continue
			}
			if e.isDuplicate(event.IP) {
				e.stats.skipped.Add(1)
				continue
			}
			// Pre-register in banned so duplicate events in the same batch are caught.
			e.mu.Lock()
			e.banned[event.IP] = time.Now()
			e.mu.Unlock()
			buffer = append(buffer, event)
			if len(buffer) >= e.cfg.BatchSize {
				e.flushLocked(ctx)
				buffer = buffer[:0]
			}
		case <-tickerFlush.C:
			if len(buffer) > 0 {
				e.flushLocked(ctx)
				buffer = buffer[:0]
			}
		case <-tickerSweep.C:
			e.sweep(ctx)
		}
	}
}

// flushLocked snapshots the banned map under the lock and calls flush.
func (e *NginxExecutor) flushLocked(ctx context.Context) {
	e.mu.RLock()
	bannedSnapshot := make(map[string]time.Time, len(e.banned))
	for ip, addedAt := range e.banned {
		bannedSnapshot[ip] = addedAt
	}
	e.mu.RUnlock()

	e.flush(ctx, bannedSnapshot)
}

// ++++++++++++++++++++++++++ Helpers +++++++++++++++++++++++++++++++++++++++++

func (e *NginxExecutor) Stats() plugin.ExecutorStats {
	return plugin.ExecutorStats{
		Executed: e.stats.executed.Load(),
		Skipped:  e.stats.skipped.Load(),
		Errors:   e.stats.errors.Load(),
	}
}

func (e *NginxExecutor) meetsMinLevel(level string) bool {
	if _, ok := levelOrder[level]; !ok {
		return false
	}
	return levelOrder[level] >= levelOrder[e.cfg.MinLevel]
}

func (e *NginxExecutor) isDuplicate(ip string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	_, exists := e.banned[ip]
	return exists
}
