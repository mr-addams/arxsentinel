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

	"github.com/mr-addams/arxsentinel/internal/sys/config"
	"github.com/mr-addams/arxsentinel/internal/sys/utils"
	"github.com/mr-addams/arxsentinel/pkg/plugin"
)

const defaultSweepInterval = 15 * time.Minute

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

	mu     sync.RWMutex
	banned map[string]time.Time

	stats struct {
		executed atomic.Int64
		skipped  atomic.Int64
		errors   atomic.Int64
	}
}

// ++++++++++++++++++++++++++ Constructor +++++++++++++++++++++++++++++++++++++

// NewNginxExecutor creates a new NginxExecutor from a config.ExecutorItem.
// It parses the config, logs a WARNING if ReloadCmd is empty, and
// initialises the banned map.
func NewNginxExecutor(cfg config.ExecutorItem) (plugin.Executor, error) {
	parsed, err := parseConfig(cfg.Config)
	if err != nil {
		return nil, fmt.Errorf("nginx: new executor: %w", err)
	}

	if parsed.TTL <= 0 {
		return nil, fmt.Errorf("nginx: new executor: TTL must be positive, got %v", parsed.TTL)
	}

	if parsed.ReloadCmd == "" {
		utils.Log("EXECUTOR", fmt.Sprintf("nginx executor %q: reload_cmd is empty — bans are written but nginx will not be reloaded automatically", cfg.Name), "warning")
	}

	return &NginxExecutor{
		name:     cfg.Name,
		execType: "nginx",
		cfg:      parsed,
		banned:   make(map[string]time.Time),
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
// Writes to path + ".tmp", calls Sync(), then renames to path.
// This prevents nginx from reading a partially written file.
func writeFile(path, data string) error {
	dir := filepath.Dir(path)
	tmpPath := path + ".tmp"
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("writeFile: mkdir: %w", err)
	}
	if err := os.WriteFile(tmpPath, []byte(data), 0644); err != nil {
		return fmt.Errorf("writeFile: write tmp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("writeFile: rename: %w", err)
	}
	return nil
}

// saveState writes the banned map as a JSON file at StateFile (if configured).
// Format: {"ip": "2026-06-01T12:00:00Z", ...}.
func (e *NginxExecutor) saveState(banned map[string]time.Time) {
	if e.cfg.StateFile == "" {
		return
	}
	data, err := json.Marshal(banned)
	if err != nil {
		e.stats.errors.Add(1)
		utils.Log("EXECUTOR", fmt.Sprintf("nginx executor %q: saveState marshal: %v", e.name, err), "error")
		return
	}
	if err := writeFile(e.cfg.StateFile, string(data)); err != nil {
		e.stats.errors.Add(1)
		utils.Log("EXECUTOR", fmt.Sprintf("nginx executor %q: saveState write: %v", e.name, err), "error")
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
				utils.Log("EXECUTOR", fmt.Sprintf("nginx executor %q: state file %q is corrupted (invalid JSON) — ignoring, TTL will be calculated from now", e.name, e.cfg.StateFile), "warning")
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
		utils.Log("EXECUTOR", fmt.Sprintf("nginx executor %q: syncExisting: read error: %v — banned map may be incomplete", e.name, err), "warning")
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
		utils.Log("EXECUTOR", fmt.Sprintf("nginx executor %q: reload failed: %v — output: %s", e.name, err, strings.TrimSpace(string(output))), "error")
		return
	}
	if len(output) > 0 {
		utils.Log("EXECUTOR", fmt.Sprintf("nginx executor %q: reload output: %s", e.name, strings.TrimSpace(string(output))), "info")
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
	if len(banned) == 0 {
		return
	}

	var sb strings.Builder
	sb.WriteString(fileHeader)
	for ip := range banned {
		sb.WriteString(fmt.Sprintf("%s 1;\n", ip))
	}

	if err := writeFile(e.cfg.ListFile, sb.String()); err != nil {
		e.stats.errors.Add(1)
		utils.Log("EXECUTOR", fmt.Sprintf("nginx executor %q: flush write: %v", e.name, err), "error")
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
	tickerSweep := time.NewTicker(sweepInterval)
	defer tickerSweep.Stop()

	// Internal channel for events — Pop is not channel-based.
	events := make(chan plugin.ThreatEvent, e.cfg.BatchSize)
	go func() {
		defer close(events)
		for {
			event, err := source.Pop(ctx)
			if err != nil {
				return
			}
			select {
			case events <- event:
			case <-ctx.Done():
				return
			}
		}
	}()

	buffer := make([]plugin.ThreatEvent, 0, e.cfg.BatchSize)

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
