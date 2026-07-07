// ====== Module: mikrotik — executor ==============================================
//
//	MikroTikExecutor manages a RouterOS firewall address-list via the REST API.
//	Receives ThreatEvents, accumulates them in a buffer, and flushes to RouterOS
//	(with TTL-based sweep, dedup, min-level filtering).
//
//	WHAT IS HERE:
//	  MikroTikExecutor struct, Run loop, flush, sweep, syncExisting
//
//	WHAT IS NOT HERE:
//	  HTTP client (client.go), config parsing (config.go), registration (register.go)
//
//	Gate B (Flow 083 / Task 3.3 / RESOLVED-D): ThreatEvent lives in the
//	product namespace cmd/arxsentinel/internal/threat; the executor
//	type-asserts Event.Payload to *threat.ThreatEvent to extract the IP
//	and level fields. Core has no knowledge of the payload shape.
package mikrotik

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/mr-addams/arx-core/pkg/dedup"
	"github.com/mr-addams/arx-core/pkg/executor"
	"github.com/mr-addams/arx-core/pkg/logger"
	"github.com/mr-addams/arx-core/pkg/plugin"

	"github.com/mr-addams/arxsentinel/internal/threat"
)

const (
	sentinelPrefix = "sentinel-"

	// defaultSweepInterval is used when TTL is zero (permanent) or TTL/4 < 15m.
	defaultSweepInterval = 15 * time.Minute
)

// NewMikroTikExecutor creates a new MikroTik executor from a generic
// executor.ExecutorConfig (Flow 073 / Task 1.3.1 — was config.ExecutorItem
// pre-1.3.1). The raw cfg.Config map is forwarded to parseConfig() which
// validates the implementation-specific block; only cfg.Name is consumed
// at this layer for the executor identity.
//
// `log` is the operational logger injected by the registry factory. The
// pre-1.3.1 wiring passed logger.Nop here, which silently swallowed
// EXECUTOR-tag diagnostics — this is the F1 closure point in MikroTik.
func NewMikroTikExecutor(cfg executor.ExecutorConfig, log logger.Logger) (plugin.Executor, error) {
	parsed, err := parseConfig(cfg.Config)
	if err != nil {
		return nil, fmt.Errorf("mikrotik: new executor: %w", err)
	}

	// Inject the operational logger. nil is replaced with logger.Nop so
	// downstream code never has to nil-check. See Flow 072 Decision 2.
	if log == nil {
		log = logger.Nop
	}

	client := NewHTTPClient(parsed.Host, parsed.Port, parsed.Username, parsed.Password, parsed.TLSVerify, parsed.CAFile, parsed.UseTLS)

	exec := &MikroTikExecutor{
		name:     cfg.Name,
		cfg:      parsed,
		client:   client,
		banned:   make(map[string]banRecord),
		dedupWin: dedup.NewWindow(parsed.DedupWindow),
		logger:   log,
	}

	return exec, nil
}

// syncExisting loads existing address-list entries into the banned map.
// Only entries whose comment matches sentinelPrefix + SentinelID are loaded.
func (e *MikroTikExecutor) syncExisting(ctx context.Context) error {
	entries, err := e.client.List(ctx, e.cfg.ListName)
	if err != nil {
		return err
	}

	prefix := sentinelPrefix + e.cfg.SentinelID

	e.mu.Lock()
	defer e.mu.Unlock()

	for _, entry := range entries {
		if entry.Comment != prefix {
			continue
		}
		e.banned[entry.Address] = banRecord{
			id:      entry.ID,
			addedAt: time.Now(),
		}
	}

	return nil
}

// Stats returns a snapshot of operational counters.
func (e *MikroTikExecutor) Stats() plugin.ExecutorStats {
	return plugin.ExecutorStats{
		Executed: e.stats.executed.Load(),
		Skipped:  e.stats.skipped.Load(),
		Errors:   e.stats.errors.Load(),
		Swept:    e.stats.swept.Load(), // monotonic swept counter
	}
}

// Run reads ThreatEvents from source, applies min-level and dedup filtering,
// accumulates them in a buffer, and flushes to the RouterOS address-list.
// Also runs a periodic sweep to remove expired bans.
func (e *MikroTikExecutor) Run(ctx context.Context, source plugin.EventSource) error {
	// Initial sync moved here from the constructor so that constructing the executor
	// (e.g. to read its Manifest in pipeline validation) performs no network I/O.
	// Non-fatal: a transient RouterOS outage at startup must not crash the daemon —
	// the ban list is rebuilt as events arrive and on the next sweep.
	if err := e.syncExisting(ctx); err != nil {
		e.logger.Log("EXECUTOR", fmt.Sprintf("mikrotik: initial sync failed: %v", err), logger.LevelWarning)
	}
	buffer := make([]threat.ThreatEvent, 0, e.cfg.BatchSize)
	flushInterval := e.cfg.FlushInterval
	if flushInterval <= 0 {
		flushInterval = 30 * time.Second // guard against zero/negative value in tests
	}
	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	sweepInterval := e.cfg.TTL / 4
	if e.cfg.TTL == 0 || sweepInterval < defaultSweepInterval {
		sweepInterval = defaultSweepInterval
	}
	sweepTicker := time.NewTicker(sweepInterval)
	defer sweepTicker.Stop()

	events := make(chan threat.ThreatEvent, 1)
	go func() {
		defer close(events)
		for {
			ev, err := source.Pop(ctx)
			if err != nil {
				return
			}
			te, ok := ev.Payload.(*threat.ThreatEvent)
			if !ok {
				fmt.Fprintf(os.Stderr, "[mikrotik executor] skipped non-ThreatEvent payload: %T\n", ev.Payload)
				continue
			}
			select {
			case events <- *te:
			case <-ctx.Done():
				return
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			e.flush(ctx, buffer)
			e.sweep(ctx)
			return ctx.Err()
		case event, ok := <-events:
			if !ok {
				e.flush(ctx, buffer)
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
			// Note: do NOT add to e.banned and do NOT call dedupWin.Mark here.
			// Both are populated only after a successful Add in flush().
			// This makes the dedup window flaky-safe: a transient RouterOS
			// error does not poison the window and the next event will retry.
			buffer = append(buffer, event)
			if len(buffer) >= e.cfg.BatchSize {
				e.flush(ctx, buffer)
				buffer = buffer[:0]
			}
		case <-ticker.C:
			if len(buffer) > 0 {
				e.flush(ctx, buffer)
				buffer = buffer[:0]
			}
		case <-sweepTicker.C:
			e.sweep(ctx)
		}
	}
}

// flush sends buffered events to the RouterOS address-list.
// Each IP receives a comment matching the sentinel prefix + SentinelID.
// Duplicates already in banned map are skipped.
func (e *MikroTikExecutor) flush(ctx context.Context, events []threat.ThreatEvent) {
	if len(events) == 0 {
		return
	}

	comment := sentinelPrefix + e.cfg.SentinelID
	timeout := durationToRouterOS(e.cfg.TTL)

	// addedIPs — IPs successfully added in this flush. We MarkBatch them in a
	// single call after the loop (see below) to avoid taking the mutex N times.
	addedIPs := make([]string, 0, len(events))

	e.mu.Lock()
	unique := make([]threat.ThreatEvent, 0, len(events))
	for _, ev := range events {
		if _, exists := e.banned[ev.IP]; exists {
			e.stats.skipped.Add(1)
			continue
		}
		unique = append(unique, ev)
	}
	e.mu.Unlock()

	if len(unique) == 0 {
		return
	}

	for _, ev := range unique {
		id, err := e.client.Add(ctx, AddressListEntry{
			Address: ev.IP,
			List:    e.cfg.ListName,
			Timeout: timeout,
			Comment: comment,
		})
		if err != nil {
			e.logger.Log("EXECUTOR", fmt.Sprintf("mikrotik: flush: add %s: %v", ev.IP, err), logger.LevelError)
			e.stats.errors.Add(1)
			// Do not mark the IP in the dedup window on error — otherwise a flaky RouterOS
			// would cause the IP to be blocked in the window for the whole TTL,
			// even though the ban was not actually applied. The next event will
			// arrive and try again.
			continue
		}
		e.mu.Lock()
		e.banned[ev.IP] = banRecord{id: id, addedAt: time.Now()}
		e.mu.Unlock()
		// Collect successfully banned IPs — MarkBatch at the end of flush will
		// mark them with a SINGLE mutex acquisition (instead of N separate Marks).
		// Semantics identical to N individual Mark calls: each IP gets the TTL,
		// the dedup window stays flaky-safe (failed Adds are not in the batch).
		addedIPs = append(addedIPs, ev.IP)
		e.stats.executed.Add(1)
	}

	// One batch-mark after the loop — cheaper than N mutex acquisitions on a large flush.
	if len(addedIPs) > 0 {
		e.dedupWin.MarkBatch(addedIPs)
	}
}

// sweep removes expired bans from RouterOS and the local banned map.
// Only entries that were added by this executor (sentinel prefix match) are removed.
// If TTL is zero (permanent ban), no entries are swept.
//
// Two-phase cleanup:
//
//	Phase 1 — collect expired IDs under lock.
//	Phase 2 — delete from RouterOS. Only remove from banned map on success.
//	This prevents the "lost ban" scenario: if API delete fails, the entry stays
//	in the map and will be retried on the next sweep cycle.
func (e *MikroTikExecutor) sweep(ctx context.Context) {
	if e.cfg.TTL == 0 {
		return
	}

	e.mu.Lock()
	expired := make([]expiredEntry, 0, len(e.banned))
	now := time.Now()
	for ip, rec := range e.banned {
		if rec.id != "" && now.Sub(rec.addedAt) > e.cfg.TTL {
			expired = append(expired, expiredEntry{id: rec.id, ip: ip})
		}
	}
	e.mu.Unlock()

	if len(expired) == 0 {
		return
	}

	// Phase 2: delete from RouterOS, collect successful deletions.
	// Batch-remove from banned map under a single lock to minimise contention.
	successful := make([]string, 0, len(expired))
	for _, entry := range expired {
		if err := e.client.Delete(ctx, entry.id); err != nil {
			e.logger.Log("EXECUTOR", fmt.Sprintf("mikrotik: sweep: delete %s: %v", entry.id, err), logger.LevelError)
			e.stats.errors.Add(1)
			// Keep entry in banned map — next sweep will retry.
			continue
		}
		successful = append(successful, entry.ip)
	}

	// Batch cleanup: one lock, N deletes.
	if len(successful) > 0 {
		e.mu.Lock()
		for _, ip := range successful {
			delete(e.banned, ip)
		}
		e.mu.Unlock()
		// Monotonic swept counter, one Add per batch — matches Cloudflare convention.
		e.stats.swept.Add(int64(len(successful)))
	}
}

// meetsMinLevel checks if the event level meets or exceeds the configured minimum.
func (e *MikroTikExecutor) meetsMinLevel(level string) bool {
	if _, ok := levelOrder[level]; !ok {
		return false
	}
	return levelOrder[level] >= levelOrder[e.cfg.MinLevel]
}

// isDuplicate checks whether the IP was banned within the dedup window, or whether it
// is present in the local banned map. Uses a pure Contains (no side effect):
// Mark is called separately from flush() after a successful Add — this makes the
// dedup window flaky-safe (RouterOS failures do not poison the window).
//
// The dedup-window check runs first because it covers the post-sweep scenario
// (the IP has been removed from the banned map by TTL but is still in the window) —
// checking the maps in the opposite order would cause an extra API call.
func (e *MikroTikExecutor) isDuplicate(ip string) bool {
	if e.dedupWin.Contains(ip) {
		return true
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	_, exists := e.banned[ip]
	return exists
}
