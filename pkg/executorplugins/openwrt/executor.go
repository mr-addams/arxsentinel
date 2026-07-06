// ====== Module: openwrt — executor ==============================================
//   OpenwrtExecutor manages an nftables ipset on a remote OpenWrt router via
//   ubus (uhttpd-mod-ubus). Receives ThreatEvents, batches them, and flushes
//   through a single batched UCI transaction per cycle (one add_list for
//   pending bans + one del_list for locally-expired bans + ONE uci.commit +
//   ONE rc.init reload) — see DECISIONS.md Decision 3 and Decision 4.
//
//   WHAT IS HERE:
//     Constructor NewOpenwrtExecutor, Run loop, batched flush, syncExisting,
//     min-level filter, dedup check, periodic sweep, Stats snapshot.
//
//   WHAT IS NOT HERE:
//     ubus client (client.go), config parsing (config.go), registration
//     (register.go).
//
//   Gate B (Flow 083 / Task 3.3 / RESOLVED-D): ThreatEvent lives in the
//   product namespace cmd/arxsentinel/internal/threat; the executor
//   type-asserts Event.Payload to *threat.ThreatEvent to extract the IP
//   and level fields. Core has no knowledge of the payload shape.
//
//   DIFFERENCE FROM MIKROTIK:
//   The sweep mechanism is integrated into the SAME flush cycle instead of
//   being a separate method. Reason: OpenWrt requires ONE commit + ONE
//   reload per cycle (fw4 rebuilds the entire nftables ruleset on reload,
//   so issuing N reloads for N sweep deletions would be a thundering-herd
//   problem and would also reset per-entry nftables timers). MikroTik, by
//   contrast, has a native per-entry timeout and can absorb independent
//   deletes without reloading the firewall. Here we collapse add + sweep
//   delete into a single UCI transaction: one commit, one reload.

package openwrt

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
	// defaultSweepInterval is the floor for the periodic sweep ticker.
	// We never want to hammer the router with flushes for very small TTLs
	// (a TTL of 4s would otherwise yield a 1s sweep — wasteful and noisy).
	// Mirrors the mikrotik default (15m) for consistency between executors.
	defaultSweepInterval = 15 * time.Minute
)

// NewOpenwrtExecutor builds a configured executor instance from a generic
// executor.ExecutorConfig. Mirrors the mikrotik pattern: parseConfig
// validates the implementation-specific block, the constructor wires up
// collaborators (client, dedup window, logger) and the storage needed by
// the Run loop.
//
// `log` is the operational logger injected by the registry factory. nil
// is replaced with logger.Nop so downstream code never nil-checks. See
// Flow 072 Decision 2 for the rationale on logger injection.
func NewOpenwrtExecutor(cfg executor.ExecutorConfig, log logger.Logger) (plugin.Executor, error) {
	parsed, err := parseConfig(cfg.Config)
	if err != nil {
		return nil, fmt.Errorf("openwrt: new executor: %w", err)
	}

	// Inject the operational logger. nil is replaced with logger.Nop.
	if log == nil {
		log = logger.Nop
	}

	client := NewHTTPClient(parsed)

	exec := &OpenwrtExecutor{
		cfg:      parsed,
		client:   client,
		banned:   make(map[string]banRecord),
		dedupWin: dedup.NewWindow(parsed.DedupWindow),
		logger:   log,
	}

	return exec, nil
}

// syncExisting loads existing UCI ipset entries into the local banned
// map so the executor can reason about "already banned" and TTL after a
// restart.
//
// CONSERVATIVE TTL ASSUMPTION (documented limitation): the UCI store does
// not preserve per-entry timestamps (it only stores "list entry '<ip>'"),
// so after a daemon restart we cannot know when each IP was added. We
// pessimistically set expireAt = now + cfg.TTL — this grants each
// pre-existing ban a full fresh TTL window rather than expiring them
// immediately or arbitrarily. Side effect: a long-lived daemon restart
// effectively extends bans by up to one TTL. This is acceptable for a
// WAF use case (false-negatives on unbanning are vastly less harmful than
// missing a ban), and the alternative (drop the local map and resync on
// every restart) would lose dedup state and cause redundant add_list
// calls.
//
// Non-fatal: a transient router outage at startup must not crash the
// daemon — the ban list is rebuilt as events arrive and on the next
// sweep, same policy as the mikrotik equivalent.
func (e *OpenwrtExecutor) syncExisting(ctx context.Context) error {
	entries, err := e.client.ListEntries(ctx)
	if err != nil {
		return err
	}

	now := time.Now()
	expireAt := now.Add(e.cfg.TTL)

	e.mu.Lock()
	defer e.mu.Unlock()

	for _, ip := range entries {
		// No prefix/sentinel-id filter here: the UCI ipset section is fully
		// owned by this plugin instance (the user is expected to configure
		// a dedicated ipset for ArxSentinel — see README prerequisites).
		// Pre-existing entries from a previous run or a manual uci edit are
		// all treated as "ours".
		e.banned[ip] = banRecord{
			ip:       ip,
			addedAt:  now,
			expireAt: expireAt,
		}
	}

	return nil
}

// Stats returns a snapshot of operational counters. Read-only access to
// the atomic counters — no lock needed (atomic.Int64 is goroutine-safe).
func (e *OpenwrtExecutor) Stats() plugin.ExecutorStats {
	return plugin.ExecutorStats{
		Executed: e.stats.executed.Load(),
		Skipped:  e.stats.skipped.Load(),
		Errors:   e.stats.errors.Load(),
		Swept:    e.stats.swept.Load(), // monotonic swept counter
	}
}

// Run reads ThreatEvents from source, applies min-level and dedup
// filtering, accumulates them in a buffer, and flushes to the router.
// The flush cycle also performs the periodic sweep: pending-to-add and
// locally-expired IPs are committed in ONE UCI transaction, then ONE
// rc.init reload applies the change. This is the key difference from
// the mikrotik executor (which can issue independent deletes thanks to
// RouterOS' per-entry timeout — see file header).
//
// Initial syncExisting runs once at startup and is non-fatal.
func (e *OpenwrtExecutor) Run(ctx context.Context, source plugin.EventSource) error {
	// Initial sync moved here from the constructor so constructing the
	// executor (e.g. to read its Manifest in pipeline validation) performs
	// no network I/O.
	if err := e.syncExisting(ctx); err != nil {
		e.logger.Log("EXECUTOR", fmt.Sprintf("openwrt: initial sync failed: %v", err), logger.LevelWarning)
	}

	// Guard against zero/negative flush interval (defensive — parseConfig
	// already enforces sensible defaults, but a test-injected value could
	// still bypass that path).
	flushInterval := e.cfg.FlushInterval
	if flushInterval <= 0 {
		flushInterval = 30 * time.Second
	}
	flushTicker := time.NewTicker(flushInterval)
	defer flushTicker.Stop()

	// Sweep ticker — drives periodic flushes even when no new events
	// arrive, so locally-expired IPs get removed in bounded time.
	// Floor at defaultSweepInterval: a 4s TTL would otherwise yield a 1s
	// sweep ticker, which is wasteful.
	sweepInterval := e.cfg.TTL / 4
	if e.cfg.TTL == 0 || sweepInterval < defaultSweepInterval {
		sweepInterval = defaultSweepInterval
	}
	sweepTicker := time.NewTicker(sweepInterval)
	defer sweepTicker.Stop()

	// events is the internal channel that decouples source.Pop (which may
	// block on an upstream queue) from the per-event filter pipeline.
	// Buffer of 1 is sufficient: the main loop is fast (just filter +
	// append), so back-pressure to source.Pop is the intended behaviour.
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
				fmt.Fprintf(os.Stderr, "[openwrt executor] skipped non-ThreatEvent payload: %T\n", ev.Payload)
				continue
			}
			select {
			case events <- *te:
			case <-ctx.Done():
				return
			}
		}
	}()

	// pending carries IPs queued for the next flush. The main loop
	// appends on event intake; flush() drains the slice and resets it.
	pending := make([]string, 0, e.cfg.BatchSize)

	for {
		select {
		case <-ctx.Done():
			// Graceful shutdown: best-effort final flush of whatever
			// is still queued. Errors are logged but do not block
			// the return — ctx is already cancelled, the caller
			// is not waiting on further state changes.
			e.flush(ctx, pending)
			return ctx.Err()
		case event, ok := <-events:
			if !ok {
				// Source closed cleanly (e.g. pipeline shutdown
				// without ctx cancellation) — flush and exit.
				e.flush(ctx, pending)
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
			// Note: do NOT add to e.banned and do NOT call dedupWin.Mark
			// here. Both are populated only after a successful AddEntries
			// in flush(). This makes the dedup window flaky-safe: a
			// transient router error does not poison the window and the
			// next event will retry.
			pending = append(pending, event.IP)
			if len(pending) >= e.cfg.BatchSize {
				e.flush(ctx, pending)
				pending = pending[:0]
			}
		case <-flushTicker.C:
			if len(pending) > 0 {
				e.flush(ctx, pending)
				pending = pending[:0]
			}
		case <-sweepTicker.C:
			// Sweep ticker: pass nil to flush — only sweep-expired
			// deletions are applied this cycle (no pending adds).
			// flush() detects the empty pending list and skips the
			// add_list call; if no IPs are expired either, the
			// entire cycle is a no-op.
			e.flush(ctx, nil)
		}
	}
}

// flush drains pending-to-add IPs and, in the same UCI transaction,
// removes locally-expired entries from e.banned. The cycle ends with
// at most ONE uci.commit and ONE rc.init reload — even if both add and
// delete lists are non-empty. This is the core of the batched-apply
// strategy from DECISIONS.md Decision 4.
//
// pending may be nil/empty (sweep-only path); in that case the add
// branch is skipped entirely.
//
// Errors are logged and counted, never returned — Run() must keep
// looping even if the router flaps. The dedup window and the banned
// map are only updated on success, so the next event re-tries the
// operation naturally.
func (e *OpenwrtExecutor) flush(ctx context.Context, pending []string) {
	// Phase 1 — under lock: split pending into (newly-banned, already-in-map)
	// and collect locally-expired IPs from the banned map.
	e.mu.Lock()
	now := time.Now()

	// Deduplicate pending against the banned map. The main loop already
	// checks isDuplicate, but a second flush can race (e.g. an event
	// arrives while the previous flush is in flight), so we filter again
	// here under the lock to be safe.
	uniquePending := make([]string, 0, len(pending))
	for _, ip := range pending {
		if _, exists := e.banned[ip]; exists {
			e.stats.skipped.Add(1)
			continue
		}
		uniquePending = append(uniquePending, ip)
	}

	// Collect expired IPs. We compare expireAt (not addedAt) because the
	// banned map can contain entries from syncExisting whose expireAt
	// is set to now+TTL (conservative assumption — see syncExisting
	// comment).
	var expired []string
	for ip, rec := range e.banned {
		if !rec.expireAt.After(now) {
			expired = append(expired, ip)
		}
	}
	e.mu.Unlock()

	// If both branches are empty, there is nothing to do — skip the
	// commit + reload entirely. This is critical for the sweep ticker
	// firing on an idle system: we MUST NOT issue a no-op commit + reload
	// every 15 minutes when nothing changed (would reset fw4 state for
	// no reason and could mask real firewall churn).
	if len(uniquePending) == 0 && len(expired) == 0 {
		return
	}

	// Phase 2 — issue the UCI operations. Order: add first, then delete,
	// so that an IP that is both being added (was never in banned map)
	// and somehow in the delete batch (race during this flush) is
	// net-added. In practice uniquePending and expired are disjoint
	// because uniquePending was filtered against the banned map while
	// holding the lock, but the order is defensive.

	addedOK := false
	if len(uniquePending) > 0 {
		if err := e.client.AddEntries(ctx, uniquePending); err != nil {
			e.logger.Log("EXECUTOR", fmt.Sprintf("openwrt: flush: add_list %d entries: %v", len(uniquePending), err), logger.LevelError)
			e.stats.errors.Add(1)
		} else {
			addedOK = true
		}
	}

	deletedOK := false
	if len(expired) > 0 {
		if err := e.client.DeleteEntries(ctx, expired); err != nil {
			e.logger.Log("EXECUTOR", fmt.Sprintf("openwrt: flush: del_list %d entries: %v", len(expired), err), logger.LevelError)
			e.stats.errors.Add(1)
		} else {
			deletedOK = true
		}
	}

	// Single commit + single reload for the whole cycle, but only if at
	// least one of the UCI mutations succeeded. If both failed, there is
	// nothing to apply — do not commit an empty transaction.
	if addedOK || deletedOK {
		if err := e.client.Commit(ctx); err != nil {
			e.logger.Log("EXECUTOR", fmt.Sprintf("openwrt: flush: commit: %v", err), logger.LevelError)
			e.stats.errors.Add(1)
		}
		if err := e.client.Reload(ctx); err != nil {
			e.logger.Log("EXECUTOR", fmt.Sprintf("openwrt: flush: reload: %v", err), logger.LevelError)
			e.stats.errors.Add(1)
		}
	}

	// Phase 3 — under lock: update local state to reflect what was
	// actually applied. On add failure, do NOT add to banned map / dedup
	// (flaky-safe: the next event will retry). On delete failure, do NOT
	// remove from banned map (the next sweep will retry). On partial
	// success, update only the corresponding half.
	e.mu.Lock()
	defer e.mu.Unlock()

	now = time.Now()
	expireAt := now.Add(e.cfg.TTL)

	if addedOK {
		addedIPs := make([]string, 0, len(uniquePending))
		for _, ip := range uniquePending {
			e.banned[ip] = banRecord{
				ip:       ip,
				addedAt:  now,
				expireAt: expireAt,
			}
			addedIPs = append(addedIPs, ip)
		}
		// MarkBatch is cheaper than N individual Mark calls (one mutex
		// acquisition vs. N). See dedup.MarkBatch doc.
		e.dedupWin.MarkBatch(addedIPs)
		e.stats.executed.Add(int64(len(addedIPs)))
	}

	if deletedOK {
		for _, ip := range expired {
			delete(e.banned, ip)
		}
		e.stats.swept.Add(int64(len(expired)))
	}
}

// meetsMinLevel checks if the event level meets or exceeds the
// configured minimum. Unknown levels are treated as below threshold —
// the contract says levels are INFO/WARN/THREAT and anything else is
// either a bug upstream or a future value the executor was not
// configured for.
func (e *OpenwrtExecutor) meetsMinLevel(level string) bool {
	if _, ok := levelOrder[level]; !ok {
		return false
	}
	return levelOrder[level] >= levelOrder[e.cfg.MinLevel]
}

// isDuplicate reports whether an IP should be skipped on the
// "already-banned" basis. Two checks: dedup window (recent successful
// add within DedupWindow TTL — survives sweep-removal) and the local
// banned map (currently in our bookkeeping as an active ban).
//
// Contains is checked first because it is the cheaper path and also
// covers the post-sweep case: an IP was swept out of the banned map
// but is still inside the dedup window. Flipping the order would cause
// a redundant add_list call in that scenario.
//
// This is a pure lookup (no side-effect): Mark/MarkBatch is invoked
// from flush() after a successful AddEntries, which makes the dedup
// window flaky-safe — a failed AddEntries does not poison the window.
func (e *OpenwrtExecutor) isDuplicate(ip string) bool {
	if e.dedupWin.Contains(ip) {
		return true
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	_, exists := e.banned[ip]
	return exists
}
