// ====== Module: mikrotik — executor ==============================================
//   MikroTikExecutor manages a RouterOS firewall address-list via the REST API.
//   Receives ThreatEvents, accumulates them in a buffer, and flushes to RouterOS
//   (with TTL-based sweep, dedup, min-level filtering).
//
//   WHAT IS HERE:
//     MikroTikExecutor struct, Run loop, flush, sweep, syncExisting
//
//   WHAT IS NOT HERE:
//     HTTP client (client.go), config parsing (config.go), registration (register.go)

package mikrotik

import (
	"context"
	"fmt"
	"time"

	"github.com/mr-addams/arxsentinel/internal/sys/config"
	"github.com/mr-addams/arxsentinel/internal/sys/utils"
	"github.com/mr-addams/arxsentinel/pkg/dedup"
	"github.com/mr-addams/arxsentinel/pkg/plugin"
)

const (
	sentinelPrefix = "sentinel-"

	// defaultSweepInterval is used when TTL is zero (permanent) or TTL/4 < 15m.
	defaultSweepInterval = 15 * time.Minute
)

// NewMikroTikExecutor creates a new MikroTik executor from an ExecutorItem config.
func NewMikroTikExecutor(cfg config.ExecutorItem) (plugin.Executor, error) {
	parsed, err := parseConfig(cfg.Config)
	if err != nil {
		return nil, fmt.Errorf("mikrotik: new executor: %w", err)
	}

	client := NewHTTPClient(parsed.Host, parsed.Port, parsed.Username, parsed.Password, parsed.TLSVerify, parsed.CAFile, parsed.UseTLS)

	exec := &MikroTikExecutor{
		name:     cfg.Name,
		cfg:      parsed,
		client:   client,
		banned:   make(map[string]banRecord),
		dedupWin: dedup.NewWindow(parsed.DedupWindow),
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
		utils.Log("EXECUTOR", fmt.Sprintf("mikrotik: initial sync failed: %v", err), "warning")
	}
	buffer := make([]plugin.ThreatEvent, 0, e.cfg.BatchSize)
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

	events := make(chan plugin.ThreatEvent, 1)
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
func (e *MikroTikExecutor) flush(ctx context.Context, events []plugin.ThreatEvent) {
	if len(events) == 0 {
		return
	}

	comment := sentinelPrefix + e.cfg.SentinelID
	timeout := durationToRouterOS(e.cfg.TTL)

	// addedIPs — IP, успешно добавленные в этом flush. MarkBatch'им их
	// одним вызовом после цикла (см. ниже), чтобы не брать mutex N раз.
	addedIPs := make([]string, 0, len(events))

	e.mu.Lock()
	unique := make([]plugin.ThreatEvent, 0, len(events))
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
			utils.Log("EXECUTOR", fmt.Sprintf("mikrotik: flush: add %s: %v", ev.IP, err), "error")
			e.stats.errors.Add(1)
			// Не помечаем IP в dedup-окне при ошибке — иначе flaky RouterOS
			// приведёт к тому, что IP будет заблокирован в окне на TTL,
			// хотя фактически бан не применился. Следующий event дойдёт
			// снова и попробует заново.
			continue
		}
		e.mu.Lock()
		e.banned[ev.IP] = banRecord{id: id, addedAt: time.Now()}
		e.mu.Unlock()
		// Собираем успешно забаненные IP — MarkBatch в конце flush
		// пометит их ОДНИМ взятием mutex (вместо N отдельных Mark).
		// Семантика идентична N вызовам Mark: каждый IP получает TTL,
		// dedup-окно остаётся flaky-safe (failed Add не попадает в батч).
		addedIPs = append(addedIPs, ev.IP)
		e.stats.executed.Add(1)
	}

	// Один batch-mark после цикла — дешевле N взятий mutex при большом flush.
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
			utils.Log("EXECUTOR", fmt.Sprintf("mikrotik: sweep: delete %s: %v", entry.id, err), "error")
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

// isDuplicate проверяет, банился ли IP в течение dedup-окна или есть ли он
// в локальной banned-map. Использует чистый Contains (без side-effect):
// Mark вызывается отдельно из flush() после успешного Add — это делает
// dedup-окно flaky-safe (RouterOS сбои не отравляют окно).
//
// Проверка dedup-окна идёт первой, потому что она покрывает post-sweep
// сценарий (IP удалён из banned-map по TTL, но ещё в окне) — проверка
// в обратном порядке привела бы к лишнему API-вызову.
func (e *MikroTikExecutor) isDuplicate(ip string) bool {
	if e.dedupWin.Contains(ip) {
		return true
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	_, exists := e.banned[ip]
	return exists
}
