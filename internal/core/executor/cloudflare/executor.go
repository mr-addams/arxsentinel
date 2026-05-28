// ========================== Package cloudflare ==========================
//   CloudflareExecutor — a plugin.Executor implementation that manages
//   Cloudflare IP blocklists with automatic TTL-based sweeping.
//
//   WHAT IS HERE:
//     - levelOrder — threat-level to numeric-rank mapping
//     - banRecord — local in-memory record of a banned IP
//     - CloudflareExecutor struct and all interface methods
//     - Sweep goroutine for expiring stale bans
//
//   WHAT IS NOT HERE:
//     - HTTP client implementation (see client.go)
//     - Config parsing (see config.go)
//     - Factory registration (done in registry.go via init())

package cloudflare

import (
	// ── Standard library ──────────────────────────────────────────────────
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	// ── Internal dependencies ──────────────────────────────────────────────
	"github.com/mr-addams/arxsentinel/internal/sys/config"
	"github.com/mr-addams/arxsentinel/pkg/plugin"
)

// ========================== Package-level helpers ==========================

// threatLevel represents the numeric rank of a threat severity.
type threatLevel int

const (
	levelInfo   threatLevel = iota
	levelWarn
	levelThreat
)

// levelOrder maps threat level strings to numeric rank, enabling comparison.
// Lower values mean lower severity. Used by Execute to skip events below the
// configured MinLevel threshold.
var levelOrder = map[string]threatLevel{
	"INFO":   levelInfo,
	"WARN":   levelWarn,
	"THREAT": levelThreat,
}

// defaultSweepInterval is the minimum interval between sweep cycles.
// When cfg.TTL/4 is shorter than this, sweepExpired falls back to 15 min
// to avoid excessive API calls on very short TTL values.
const defaultSweepInterval = 15 * time.Minute

// ========================== banRecord ==========================

// banRecord stores the local state of a single banned IP.
// The IP itself is the map key, not stored in the struct.
//   - cfItemID is populated from the Cloudflare API response on add or during
//     the first sweep cycle; items added by external sources get it on sync.
//   - addedByExecutor distinguishes between items we added ourselves vs items
//     that already existed when we synced — both are managed by sweeper, but
//     the flag is reserved for future metrics or selective cleanup.
type banRecord struct {
	cfItemID        string
	addedAt         time.Time
	addedByExecutor bool
}

// ========================== CloudflareExecutor ==========================

// CloudflareExecutor implements plugin.Executor for Cloudflare IP Lists.
//
// Lifecycle:
//  1. NewCloudflareExecutor — parse config, create client, resolve list,
//     sync existing items, launch sweep goroutine.
//  2. Execute — on each threat event, check threshold & dedup, add to CF.
//  3. Sweep goroutine — periodically removes expired bans.
//  4. Close — cancel sweep, wait for goroutine, release resources.
type CloudflareExecutor struct {
	// name is the human-readable identifier from ExecutorItem.Name,
	// returned by Name() and used in pipeline logs / metrics.
	name string

	// cfg is the parsed Cloudflare-specific configuration after validation.
	cfg Config

	// client is the CFClient implementation (production HTTP or test mock).
	client CFClient

	// listID is the Cloudflare IP List identifier obtained at startup.
	listID string

	// mu protects the banned map — the only shared mutable state.
	mu sync.Mutex

	// banned holds all IPs currently tracked by this executor, indexed by IP.
	// Items may originate from our own Execute calls (addedByExecutor=true)
	// or from pre-existing list entries discovered during syncExisting.
	banned map[string]banRecord

	// stats accumulates operation counters for the Stats() snapshot.
	stats struct {
		executed atomic.Int64
		skipped  atomic.Int64
		errors   atomic.Int64
	}

	// stopSweep cancels the sweepExpired goroutine; set by Close().
	stopSweep context.CancelFunc

	// wg tracks the sweepExpired goroutine for clean shutdown.
	wg sync.WaitGroup
}

// ++++++++++++++++++++++++++ Constructor +++++++++++++++++++++++++++++++++++++

// NewCloudflareExecutor creates a fully initialised CloudflareExecutor from
// a pipeline configuration item.
//
// Workflow:
//  1. Parse executor-specific config via parseConfig(cfg.Config).
//  2. Create a production CFClient via NewHTTPCFClient.
//  3. Resolve or create the Cloudflare IP List (30 s timeout).
//  4. Build the executor struct with an empty banned map.
//  5. Sync existing list items into the local banned map.
//  6. Start the background sweep goroutine.
//
// The returned executor is ready for immediate Execute calls.
func NewCloudflareExecutor(cfg config.ExecutorItem) (plugin.Executor, error) {
	// ---- Parse config ----
	parsed, err := parseConfig(cfg.Config)
	if err != nil {
		return nil, fmt.Errorf("cloudflare: new executor: %w", err)
	}

	// TTL must be positive — time.NewTicker panics on non-positive interval.
	if parsed.TTL <= 0 {
		return nil, fmt.Errorf("cloudflare: new executor: TTL must be positive, got %v", parsed.TTL)
	}

	// ---- Create API client ----
	client := NewHTTPCFClient(parsed.AccountID, parsed.APIToken)

	// ---- Find or create the IP list (30 s deadline) ----
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	listID, err := client.FindOrCreateList(ctx, parsed.ListName)
	if err != nil {
		return nil, fmt.Errorf("cloudflare: new executor: %w", err)
	}

	// ---- Build executor ----
	exec := &CloudflareExecutor{
		name:   cfg.Name,
		cfg:    parsed,
		client: client,
		listID: listID,
		banned: make(map[string]banRecord),
	}

	// ---- Sync existing list items ----
	// Fresh timeout context — the constructor ctx may already be done by this point
	// because FindOrCreateList used its own derived context with defer cancel().
	syncCtx, syncCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer syncCancel()
	if err := exec.syncExisting(syncCtx); err != nil {
		return nil, fmt.Errorf("cloudflare: new executor: %w", err)
	}

	// ---- Start sweep goroutine ----
	var sweepCtx context.Context
	sweepCtx, exec.stopSweep = context.WithCancel(context.Background())
	exec.wg.Add(1)
	go exec.sweepExpired(sweepCtx)

	return exec, nil
}

// ========================== Existing item sync ==========================

// syncExisting loads every IP currently in the Cloudflare list and stores it
// in the local banned map with addedByExecutor=false. This ensures that items
// added by other systems are not duplicated and are subject to the same TTL
// management.
func (e *CloudflareExecutor) syncExisting(ctx context.Context) error {
	items, err := e.client.ListItems(ctx, e.listID)
	if err != nil {
		return fmt.Errorf("cloudflare: sync existing: %w", err)
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	for _, item := range items {
		e.banned[item.IP] = banRecord{
			cfItemID:        item.ID,
			addedAt:         time.Now(),
			addedByExecutor: false,
		}
	}

	return nil
}

// ========================== Executor interface ==========================

// ++++++++++++++++++++++++++ Execute ++++++++++++++++++++++++++++++++++++++++

// Execute processes a ThreatEvent by adding the source IP to the Cloudflare
// blocklist, subject to configured MinLevel and deduplication rules.
//
// Decision flow:
//  1. Level check — skip if event.Level < cfg.MinLevel (by numeric rank).
//  2. Dedup check — skip if IP is already in the local banned map.
//  3. API call — add IP via client.AddItem with a descriptive comment.
//  4. Local store — record the ban with addedByExecutor=true.
//
// Returns an error only when the Cloudflare API call fails. Non-nil errors
// increment the Errors counter but do not block the pipeline.
func (e *CloudflareExecutor) Execute(ctx context.Context, event plugin.ThreatEvent) error {
	// ---- Level threshold ----
	// Unknown event level — skip defensively to avoid silent misclassification.
	if _, ok := levelOrder[event.Level]; !ok {
		e.stats.skipped.Add(1)
		return nil
	}
	if levelOrder[event.Level] < levelOrder[e.cfg.MinLevel] {
		e.stats.skipped.Add(1)
		return nil
	}

	// ---- Dedup with pre-registration under lock ----
	// Pre-register the IP before the API call so that concurrent Execute calls
	// for the same IP see it as already banned and skip without a duplicate request.
	comment := fmt.Sprintf("Arxsentinel: %s @ %s", event.Reason, event.Timestamp.Format(time.RFC3339))

	e.mu.Lock()
	if _, exists := e.banned[event.IP]; exists {
		e.mu.Unlock()
		e.stats.skipped.Add(1)
		return nil
	}
	// MaxItems limit — skip if the banned list has reached capacity.
	// Zero (default) means unlimited.
	if e.cfg.MaxItems > 0 && len(e.banned) >= e.cfg.MaxItems {
		e.mu.Unlock()
		e.stats.skipped.Add(1)
		return nil
	}
	e.banned[event.IP] = banRecord{
		cfItemID:        "",
		addedAt:         time.Now(),
		addedByExecutor: true,
	}
	e.mu.Unlock()

	// ---- API call (outside the lock) ----
	itemID, err := e.client.AddItem(ctx, e.listID, event.IP, comment)
	if err != nil {
		// Roll back the pre-registration so the next Execute can retry.
		e.mu.Lock()
		delete(e.banned, event.IP)
		e.mu.Unlock()
		e.stats.errors.Add(1)
		return fmt.Errorf("cloudflare: execute: %w", err)
	}

	// Update the record with the cfItemID returned by the API (S-02).
	// Re-check under lock in case sweep removed and re-added the IP
	// between the AddItem call and this update.
	e.mu.Lock()
	if rec, ok := e.banned[event.IP]; ok && rec.cfItemID == "" {
		rec.cfItemID = itemID
		e.banned[event.IP] = rec
	}
	e.mu.Unlock()

	e.stats.executed.Add(1)
	return nil
}

// ++++++++++++++++++++++++++ isBanned +++++++++++++++++++++++++++++++++++++++

// isBanned returns true if the given IP is currently tracked in the local
// banned map. Safe for concurrent access.
func (e *CloudflareExecutor) isBanned(ip string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, ok := e.banned[ip]
	return ok
}

// ++++++++++++++++++++++++++ Name +++++++++++++++++++++++++++++++++++++++++++

// Name returns the human-readable identifier assigned in the pipeline config.
func (e *CloudflareExecutor) Name() string {
	return e.name
}

// ++++++++++++++++++++++++++ Stats ++++++++++++++++++++++++++++++++++++++++++

// Stats returns a point-in-time snapshot of operational counters.
// Safe for concurrent access — all counters use atomic operations.
func (e *CloudflareExecutor) Stats() plugin.ExecutorStats {
	return plugin.ExecutorStats{
		Executed: e.stats.executed.Load(),
		Skipped:  e.stats.skipped.Load(),
		Errors:   e.stats.errors.Load(),
	}
}

// ++++++++++++++++++++++++++ Close ++++++++++++++++++++++++++++++++++++++++++

// Close stops the sweep goroutine and waits for its completion.
// After Close returns, the executor must not be used for further Execute calls.
func (e *CloudflareExecutor) Close() error {
	e.stopSweep()
	e.wg.Wait()
	return nil
}

// ========================== Sweep logic ==========================

// ++++++++++++++++++++++++++ sweepExpired +++++++++++++++++++++++++++++++++++

// sweepExpired is the background goroutine that periodically removes expired
// bans from the Cloudflare list. It runs until the context is cancelled.
//
// The sweep interval is max(cfg.TTL/4, defaultSweepInterval) — at least
// four sweep passes per TTL window, but never more often than 15 minutes.
func (e *CloudflareExecutor) sweepExpired(ctx context.Context) {
	defer e.wg.Done()

	// Sweep interval = TTL / 4, but no less than defaultSweepInterval.
	// This ensures at least 4 sweep passes within one TTL, and never less
	// than 15 minutes to avoid excessive API calls.
	interval := e.cfg.TTL / 4
	if interval < defaultSweepInterval {
		interval = defaultSweepInterval
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.sweepOnce(ctx)
		}
	}
}

// ++++++++++++++++++++++++++ sweepOnce ++++++++++++++++++++++++++++++++++++++

// sweepOnce performs a single sweep cycle:
//  1. Check if any local records have an empty cfItemID (e.g., recently
//     added by Execute before the CF API returned the ID).
//  2. If stale IDs exist, call ListItems to refresh all entries and update
//     the local map.
//  3. Identify records whose (now - addedAt) >= cfg.TTL and have a non-empty
//     cfItemID.
//  4. Remove those IDs from the Cloudflare list via RemoveItems.
//  5. Delete the corresponding IPs from the local banned map.
//
// Errors during ListItems or RemoveItems abort the cycle silently to avoid
// cascading failures; the next tick will retry.
func (e *CloudflareExecutor) sweepOnce(ctx context.Context) {
	// ---- Step 1: check for records needing ID refresh ----
	e.mu.Lock()
	needsRefresh := false
	for _, rec := range e.banned {
		if rec.cfItemID == "" {
			needsRefresh = true
			break
		}
	}
	e.mu.Unlock()

	if needsRefresh {
		// ---- Step 2a: refresh from Cloudflare API ----
		items, err := e.client.ListItems(ctx, e.listID)
		if err != nil {
			return // skip this cycle; retry on next tick
		}

		e.mu.Lock()
		for _, item := range items {
			if rec, ok := e.banned[item.IP]; ok && rec.cfItemID == "" {
				rec.cfItemID = item.ID
				e.banned[item.IP] = rec
			}
		}
		// Lock stays held for step 3.
	} else {
		e.mu.Lock()
	}

	// ---- Step 3: find expired records ----
	now := time.Now()
	var expiredIDs []string
	var expiredIPs []string

	for ip, rec := range e.banned {
		if rec.cfItemID != "" && now.Sub(rec.addedAt) >= e.cfg.TTL {
			expiredIDs = append(expiredIDs, rec.cfItemID)
			expiredIPs = append(expiredIPs, ip)
		}
	}
	e.mu.Unlock()

	if len(expiredIDs) == 0 {
		return
	}

	// ---- Step 4: remove from Cloudflare ----
	if err := e.client.RemoveItems(ctx, e.listID, expiredIDs); err != nil {
		return // skip deletion from local map; retry on next tick
	}

	// ---- Step 5: remove from local map (re-check under lock) ----
	// Re-check addedAt under lock to avoid a race with Execute:
	// if Execute re-added the same IP between RemoveItems and this lock,
	// the new record will have a later addedAt and must not be deleted.
	e.mu.Lock()
	for _, ip := range expiredIPs {
		if rec, ok := e.banned[ip]; ok && time.Since(rec.addedAt) >= e.cfg.TTL {
			delete(e.banned, ip)
		}
	}
	e.mu.Unlock()
}
