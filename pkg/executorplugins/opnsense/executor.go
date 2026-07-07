// ====== Module: opnsense — executor ===============================================
//   OPNsenseExecutor manages a single firewall alias via OPNsense's REST API
//   (alias_util/add, alias_util/delete, alias_util/list). ThreatEvents arrive,
//   pass min-level + dedup filtering, and are applied IMMEDIATELY — one event
//   equals one REST call. There is no pending buffer, no flush ticker, and no
//   final flush on shutdown.
//
//   WHAT IS HERE:
//     Constructor NewOpnsenseExecutor, Run loop, per-event add, TTL sweep,
//     min-level filter, dedup check, Stats snapshot, syncExisting.
//
//   WHAT IS NOT HERE:
//     REST client (client.go), config parsing (config.go), registration
//     (register.go).
//
//   ARCHITECTURAL MODEL — MIKROTIK-STYLE, NOT OPENWRT-STYLE:
//     Unlike OpenWrt, which batches add_list/del_list changes behind a single
//     uci.commit + rc.init reload, OPNsense's alias_util endpoints apply the
//     underlying pfctl table update per-call. There is no expensive reload
//     to amortize, so batching would add latency and complexity without a
//     corresponding firewall benefit. Therefore the executor issues an
//     independent alias_util/add for every accepted event and an independent
//     alias_util/delete for every expired IP in the sweep. See DECISIONS.md
//     Decision 1 (mikrotik-style point updates for APIs with native per-entry
//     semantics) and Decision 8 (OPNsense intentionally has no batch_size or
//     flush_interval config fields).
//
//   Gate B (Flow 083 / Task 3.3 / RESOLVED-D): ThreatEvent lives in the
//   product namespace internal/threat; the executor type-asserts Event.Payload
//   to *threat.ThreatEvent. Core has no knowledge of the payload shape.

package opnsense

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

// NewOpnsenseExecutor builds a configured OPNsense executor from a generic
// executor.ExecutorConfig. parseConfig validates the implementation-specific
// block; the constructor wires up the REST client, dedup window, logger, and
// the banned map needed by Run without performing any network I/O.
//
// `log` is the operational logger injected by the registry factory. nil is
// replaced with logger.Nop so downstream code never nil-checks; see Flow 072
// Decision 2 for the rationale on logger injection.
func NewOpnsenseExecutor(cfg executor.ExecutorConfig, log logger.Logger) (plugin.Executor, error) {
	parsed, err := parseConfig(cfg.Config)
	if err != nil {
		return nil, fmt.Errorf("opnsense: new executor: %w", err)
	}

	// Replace a nil logger with the no-op logger so every log site is safe.
	if log == nil {
		log = logger.Nop
	}

	client := NewHTTPClient(parsed)

	exec := &OpnsenseExecutor{
		name:     cfg.Name,
		cfg:      parsed,
		client:   client,
		banned:   make(map[string]banRecord),
		dedupWin: dedup.NewWindow(parsed.DedupWindow),
		logger:   log,
	}

	return exec, nil
}

// syncExisting loads the current alias entries from OPNsense into the local
// banned map so the executor can reason about "already banned" and TTL after a
// restart.
//
// CONSERVATIVE TTL ASSUMPTION (documented limitation): OPNsense's alias_util/list
// endpoint returns only the address strings in the alias' content; it does not
// expose per-entry timestamps. After a daemon restart we cannot know when each
// IP was added, so we pessimistically set expireAt = now + cfg.TTL. This grants
// each pre-existing ban a full fresh TTL window rather than expiring them
// immediately or dropping local state entirely. The side effect (a long-lived
// daemon restart can extend a ban by up to one TTL) is acceptable for a WAF
// use case: false-negatives on unbanning are less harmful than missing a ban.
//
// Non-fatal: a transient firewall outage at startup must not crash the daemon.
// The ban list is rebuilt as events arrive and retried on the next sweep.
//
// No prefix/sentinel-id filter here: the alias is fully owned by this plugin
// instance. The user is expected to configure a dedicated alias for
// ArxSentinel — see README prerequisites.
func (e *OpnsenseExecutor) syncExisting(ctx context.Context) error {
	entries, err := e.client.ListEntries(ctx)
	if err != nil {
		return err
	}

	now := time.Now()
	expireAt := now.Add(e.cfg.TTL)

	e.mu.Lock()
	defer e.mu.Unlock()

	for _, ip := range entries {
		e.banned[ip] = banRecord{
			ip:       ip,
			addedAt:  now,
			expireAt: expireAt,
		}
	}

	return nil
}

// Stats returns a snapshot of operational counters. Read-only access to the
// atomic counters — no lock needed (atomic.Int64 is goroutine-safe).
func (e *OpnsenseExecutor) Stats() plugin.ExecutorStats {
	return plugin.ExecutorStats{
		Executed: e.stats.executed.Load(),
		Skipped:  e.stats.skipped.Load(),
		Errors:   e.stats.errors.Load(),
		Swept:    e.stats.swept.Load(), // monotonic swept counter
	}
}

// Run reads ThreatEvents from source, applies min-level and dedup filtering,
// and issues an alias_util/add call for every accepted event right away.
// There is NO pending buffer, NO flush ticker, and NO final flush on shutdown:
// every event that survives filtering is immediately translated into a single
// independent REST call. The sweep ticker runs in parallel to remove expired
// bans with independent alias_util/delete calls.
//
// Initial syncExisting runs once at startup and is non-fatal.
func (e *OpnsenseExecutor) Run(ctx context.Context, source plugin.EventSource) error {
	// Initial sync moved here from the constructor so constructing the
	// executor (e.g. to read its Manifest in pipeline validation) performs
	// no network I/O.
	if err := e.syncExisting(ctx); err != nil {
		e.logger.Log("EXECUTOR", fmt.Sprintf("opnsense: initial sync failed: %v", err), logger.LevelWarning)
	}

	// Sweep interval is derived from TTL. The floor keeps the executor from
	// hammering the firewall with tiny TTLs (e.g. TTL=4s would otherwise yield
	// a 1s sweep). TTL>0 is enforced by parseConfig, but the floor is kept as
	// a defensive guard.
	sweepInterval := e.cfg.TTL / 4
	if sweepInterval < 15*time.Minute {
		sweepInterval = 15 * time.Minute
	}
	sweepTicker := time.NewTicker(sweepInterval)
	defer sweepTicker.Stop()

	// events decouples source.Pop (which may block on an upstream queue) from
	// the rest of the loop. Buffer of 1 is sufficient: the main loop is fast
	// (one filter, one dedup check, one REST call), so back-pressure to
	// source.Pop is the intended behaviour.
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
				fmt.Fprintf(os.Stderr, "[opnsense executor] skipped non-ThreatEvent payload: %T\n", ev.Payload)
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
			// No pending buffer exists, so there is nothing to flush before
			// returning. The context cancellation itself is the shutdown
			// signal, and any in-flight alias_util/add call is bound by the
			// HTTP client's 30s timeout/context.
			return ctx.Err()
		case event, ok := <-events:
			if !ok {
				// Source closed cleanly (e.g. pipeline shutdown without ctx
				// cancellation). No buffer to drain, so exit immediately.
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

			// Immediate point add — this is the key architectural difference
			// from openwrt. alias_util/add updates the pfctl table per-call,
			// so there is no batch/reload to wait for.
			if err := e.client.AddEntry(ctx, event.IP); err != nil {
				e.logger.Log("EXECUTOR", fmt.Sprintf("opnsense: add entry %s: %v", event.IP, err), logger.LevelError)
				e.stats.errors.Add(1)
				// Do NOT add to e.banned and do NOT call dedupWin.Mark on
				// failure. This keeps the dedup window flaky-safe: an
				// OPNsense outage must not poison the window; the next event
				// for this IP will retry the add.
				continue
			}

			e.mu.Lock()
			e.banned[event.IP] = banRecord{
				ip:       event.IP,
				addedAt:  time.Now(),
				expireAt: time.Now().Add(e.cfg.TTL),
			}
			e.mu.Unlock()

			// Mark only after a successful AddEntry. Single Mark is used
			// instead of MarkBatch because the OPNsense executor has no
			// batching path — each accepted event is applied independently.
			// MarkBatch would be a misleading optimisation here (it implies
			// a batch somewhere that does not exist) and would require
			// accumulating IPs first, which contradicts the immediate-apply
			// model.
			e.dedupWin.Mark(event.IP)
			e.stats.executed.Add(1)

		case <-sweepTicker.C:
			e.sweep(ctx)
		}
	}
}

// sweep removes expired IPs from OPNsense and the local banned map.
// alias_util/delete is a per-IP endpoint; there is no batch delete or reload
// mechanism to amortize, so each expired IP gets its own independent REST
// call. The two-phase design (collect under lock, then delete outside the lock)
// avoids holding the mutex during network I/O.
//
// Only IPs whose DeleteEntry succeeded are removed from e.banned; failures
// leave the record in place so the next sweep cycle retries.
func (e *OpnsenseExecutor) sweep(ctx context.Context) {
	// Phase 1 — collect expired IPs while holding the lock.
	e.mu.Lock()
	var expired []string
	now := time.Now()
	for ip, rec := range e.banned {
		if !rec.expireAt.After(now) {
			expired = append(expired, ip)
		}
	}
	e.mu.Unlock()

	if len(expired) == 0 {
		return
	}

	// Phase 2 — independent delete per IP. We cannot batch because
	// alias_util/delete accepts only one address per call (the API shape
	// is {"address":"..."}); there is no equivalent of OpenWrt's batched
	// add_list/del_list. Holding the lock during deletes would serialize
	// network waits and block incoming events, so the lock is only taken
	// for the map mutation.
	for _, ip := range expired {
		if err := e.client.DeleteEntry(ctx, ip); err != nil {
			e.logger.Log("EXECUTOR", fmt.Sprintf("opnsense: sweep: delete %s: %v", ip, err), logger.LevelError)
			e.stats.errors.Add(1)
			// Keep the IP in e.banned; the next sweep will retry.
			continue
		}

		e.mu.Lock()
		delete(e.banned, ip)
		e.mu.Unlock()

		// Increment per-IP, matching the per-IP success pattern of the
		// sweep loop. A batched Add would hide the fact that some IPs may
		// have failed above and others succeeded.
		e.stats.swept.Add(1)
	}
}

// meetsMinLevel checks if the event level meets or exceeds the configured
// minimum. Unknown levels are treated as below threshold — the contract says
// levels are INFO/WARN/THREAT and anything else is either an upstream bug or a
// future value the executor was not configured for.
func (e *OpnsenseExecutor) meetsMinLevel(level string) bool {
	if _, ok := levelOrder[level]; !ok {
		return false
	}
	return levelOrder[level] >= levelOrder[e.cfg.MinLevel]
}

// isDuplicate reports whether an IP should be skipped on the "already banned"
// basis. Two checks: dedup window (recent successful add within DedupWindow TTL
// — survives sweep-removal) and the local banned map (currently in our
// bookkeeping as an active ban).
//
// Contains is checked first because it is the cheaper path and also covers the
// post-sweep case: an IP was swept out of the banned map but is still inside
// the dedup window. Flipping the order would cause a redundant alias_util/add
// call in that scenario.
//
// This is a pure lookup (no side-effect): Mark is invoked from Run() after a
// successful AddEntry, which makes the dedup window flaky-safe — a failed
// AddEntry does not poison the window.
func (e *OpnsenseExecutor) isDuplicate(ip string) bool {
	if e.dedupWin.Contains(ip) {
		return true
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	_, exists := e.banned[ip]
	return exists
}
