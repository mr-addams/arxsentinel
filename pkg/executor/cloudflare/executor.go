// ====== Module: cloudflare — executor =============================================
//   CloudflareExecutor manages a Cloudflare IP banlist via the Lists API.
//   Receives ThreatEvents, accumulates them in a buffer, and flushes to the
//   Cloudflare API (with 429 retry, pending operation polling, TTL-based sweep).
//
//   WHAT IS HERE:
//     CloudflareExecutor struct, Run loop, flush, sweep, retry, polling logic
//
//   WHAT IS NOT HERE:
//     CF API client (client.go), config parsing (config.go), registration (register.go)

package cloudflare

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mr-addams/arxsentinel/internal/sys/config"
	"github.com/mr-addams/arxsentinel/pkg/dedup"
	"github.com/mr-addams/arxsentinel/pkg/logger"
	"github.com/mr-addams/arxsentinel/pkg/plugin"
)

type threatLevel int

const (
	levelInfo threatLevel = iota
	levelWarn
	levelThreat
)

var levelOrder = map[string]threatLevel{
	"INFO":   levelInfo,
	"WARN":   levelWarn,
	"THREAT": levelThreat,
}

const defaultSweepInterval = 15 * time.Minute

// pollDelays defines the exponential backoff intervals for polling a bulk
// operation status from Cloudflare. Total: ~31.5s before giving up.
var pollDelays = []time.Duration{
	500 * time.Millisecond,
	1 * time.Second,
	2 * time.Second,
	4 * time.Second,
	8 * time.Second,
	16 * time.Second,
}

type banRecord struct {
	cfItemID        string
	addedAt         time.Time
	addedByExecutor bool
}

type CloudflareExecutor struct {
	name       string
	execType   string
	cfg        Config
	client     CFClient
	listID     string
	instanceID string

	// logger is the operational logger injected by the caller. Replaces the
	// pre-1.2 global utils.Log dependency — see Flow 072 Decision 2. Always
	// non-nil in practice (constructor replaces nil with logger.Nop).
	logger logger.Logger

	mu     sync.RWMutex
	banned map[string]banRecord
	stats  struct {
		executed atomic.Int64
		skipped  atomic.Int64
		errors   atomic.Int64
		swept    atomic.Int64 // M7: отдельный счётчик снятых банов (sweep)
	}

	pendingMu   sync.Mutex
	pendingOpID string
	pendingOpAt time.Time

	// dedupWin — окно дедупликации поверх banned-map.
	// TTL = cfg.DedupWindow: 0 → отключено (nil-логика IsDuplicate),
	// > 0 → запрещает повторный бан одного IP в течение TTL после
	// первого успешного бана (даже если IP уже удалён из banned по TTL sweep).
	// Нужен чтобы не "долбить" CF API при активной атаке с одного IP.
	dedupWin *dedup.Window
}

func NewCloudflareExecutor(cfg config.ExecutorItem, log logger.Logger) (plugin.Executor, error) {
	parsed, err := parseConfig(cfg.Config, log)
	if err != nil {
		return nil, fmt.Errorf("cloudflare: new executor: %w", err)
	}

	if parsed.TTL <= 0 {
		return nil, fmt.Errorf("cloudflare: new executor: TTL must be positive, got %v", parsed.TTL)
	}

	// Inject the operational logger. nil is replaced with logger.Nop so
	// downstream code never has to nil-check. See Flow 072 Decision 2.
	if log == nil {
		log = logger.Nop
	}

	var client CFClient
	if parsed.APIBaseURL != "" {
		client = NewHTTPCFClientWithBaseURL(parsed.AccountID, parsed.APIToken, parsed.APIBaseURL)
	} else {
		client = NewHTTPCFClient(parsed.AccountID, parsed.APIToken)
	}

	exec := &CloudflareExecutor{
		name:       cfg.Name,
		execType:   "cloudflare",
		cfg:        parsed,
		client:     client,
		banned:     make(map[string]banRecord),
		instanceID: LoadInstanceID(&parsed),
		dedupWin:   dedup.NewWindow(parsed.DedupWindow),
		logger:     log,
	}

	return exec, nil
}

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

func (e *CloudflareExecutor) Name() string {
	return e.name
}

func (e *CloudflareExecutor) Type() string {
	return e.execType
}

// Run reads ThreatEvents from source, accumulates them in a buffer, and flushes
// to the Cloudflare API when batch_size is reached or flush_interval fires.
// Also runs a periodic sweep to remove expired bans.
func (e *CloudflareExecutor) Run(ctx context.Context, source plugin.EventSource) error {
	// FindOrCreateList + initial sync moved here from the constructor so that
	// constructing the executor (e.g. to read its Manifest) performs no network I/O.
	// FindOrCreateList is fatal: without a list ID the executor cannot operate.
	// syncExisting is non-fatal: a transient outage at startup must not crash
	// the daemon — the ban list is rebuilt as events arrive and on the next sweep.
	//
	// Bounded startup context: the original constructor wrapped these calls in a
	// 30s timeout. Preserve that so a network hang cannot block daemon startup
	// indefinitely; cancellation still propagates from the Run ctx.
	startupCtx, startupCancel := context.WithTimeout(ctx, 30*time.Second)
	listID, err := e.client.FindOrCreateList(startupCtx, e.cfg.ListName)
	if err != nil {
		startupCancel()
		e.logger.Log("EXECUTOR", fmt.Sprintf("cloudflare: find/create list failed: %v", err), logger.LevelError)
		return fmt.Errorf("cloudflare: run: find/create list: %w", err)
	}
	e.listID = listID // must be set before syncExisting/flush/sweep use it
	if err := e.syncExisting(startupCtx); err != nil {
		e.logger.Log("EXECUTOR", fmt.Sprintf("cloudflare: initial sync failed: %v", err), logger.LevelWarning)
	}
	startupCancel()

	buffer := make([]plugin.ThreatEvent, 0, e.cfg.BatchSize)
	ticker := time.NewTicker(e.cfg.FlushInterval)
	defer ticker.Stop()

	sweepInterval := e.cfg.TTL / 4
	if sweepInterval < defaultSweepInterval {
		sweepInterval = defaultSweepInterval
	}
	sweepTicker := time.NewTicker(sweepInterval)
	defer sweepTicker.Stop()

	// Pop is not a channel — feed events into an internal channel for select.
	events := make(chan plugin.ThreatEvent, 64) // L5: буфер 64 — снижает блокировки Pop при всплесках
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
			// Pre-register in banned so duplicate events in the same batch are caught.
			// dedup-окно НЕ помечаем здесь — это делает flush() после успешного
			// AddItems. Это flaky-safe: при ошибке CF API IP не отравляет окно,
			// и повторный event снова дойдёт до попытки.
			e.mu.Lock()
			e.banned[event.IP] = banRecord{addedAt: time.Now(), addedByExecutor: true}
			e.mu.Unlock()
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

// waitForPendingOp polls the pending operation until it completes, fails, or
// all retry intervals are exhausted. On success or known failure, clears pendingOpID.
// On timeout (all retries exhausted), logs a warning and clears pendingOpID so the
// next flush can proceed. Returns true if the caller may proceed with a new operation.
func (e *CloudflareExecutor) waitForPendingOp(ctx context.Context) bool {
	e.pendingMu.Lock()
	opID := e.pendingOpID
	e.pendingMu.Unlock()

	if opID == "" {
		return true
	}

	// Use a reusable timer instead of time.After to avoid accumulating
	// unreclaimed timers in the heap across multiple poll iterations.
	timer := time.NewTimer(0)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()

	for _, delay := range pollDelays {
		timer.Reset(delay)
		select {
		case <-ctx.Done():
			// Clear pending state so the next Run() starts clean on restart.
			e.pendingMu.Lock()
			e.pendingOpID = ""
			e.pendingMu.Unlock()
			return false
		case <-timer.C:
		}

		status, err := e.client.PollBulkOperation(ctx, opID)
		if err != nil {
			continue
		}
		switch status {
		case "completed":
			e.pendingMu.Lock()
			e.pendingOpID = ""
			e.pendingMu.Unlock()
			return true
		case "failed":
			e.stats.errors.Add(1)
			e.pendingMu.Lock()
			e.pendingOpID = ""
			e.pendingMu.Unlock()
			return true
		}
	}

	e.logger.Log("EXECUTOR", fmt.Sprintf("executor %s: bulk op %s timed out after polling (6 attempts, ~31.5s) - clearing to proceed", e.name, opID), logger.LevelWarning)
	e.pendingMu.Lock()
	e.pendingOpID = ""
	e.pendingMu.Unlock()
	return true
}

const (
	max429Retries     = 3
	default429Backoff = 5 * time.Second
)

// doWithRetry wraps a CF API call with 429 retry logic.
// If err contains "429", retries up to max429Retries times with default429Backoff sleep.
func (e *CloudflareExecutor) doWithRetry(ctx context.Context, fn func() (string, error)) (string, error) {
	var lastErr error
	for attempt := 0; attempt <= max429Retries; attempt++ {
		opID, err := fn()
		if err == nil {
			return opID, nil
		}
		lastErr = err
		if !strings.Contains(err.Error(), "429") {
			return "", err
		}
		if attempt == max429Retries {
			break
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(default429Backoff):
		}
	}
	return "", lastErr
}

type cfBatchItem struct {
	IP      string `json:"ip"`
	Comment string `json:"comment"`
}

func (e *CloudflareExecutor) flush(ctx context.Context, events []plugin.ThreatEvent) {
	if len(events) == 0 {
		return
	}

	if !e.waitForPendingOp(ctx) {
		return
	}

	items := make([]CFBatchItem, len(events))
	for i, ev := range events {
		items[i] = CFBatchItem{
			IP:      ev.IP,
			Comment: e.buildComment(),
		}
	}

	opID, err := e.doWithRetry(ctx, func() (string, error) {
		return e.client.AddItems(ctx, e.listID, items)
	})
	if err != nil {
		e.stats.errors.Add(int64(len(events)))
		return
	}

	if opID != "" {
		e.pendingMu.Lock()
		e.pendingOpID = opID
		e.pendingOpAt = time.Now()
		e.pendingMu.Unlock()
	}

	e.stats.executed.Add(int64(len(events)))

	e.mu.Lock()
	for _, ev := range events {
		e.banned[ev.IP] = banRecord{addedAt: time.Now(), addedByExecutor: true}
	}
	e.mu.Unlock()

	// Помечаем IP в dedup-окне только после успешного AddItems — это
	// "flaky-safe" семантика из Task 4: при ошибке CF (429, poll timeout,
	// network) IP не отравляет окно, и повторные events снова дойдут до
	// попытки. MarkBatch берёт один mutex вместо N — симметрично mikrotik flush.
	markedIPs := make([]string, len(events))
	for i, ev := range events {
		markedIPs[i] = ev.IP
	}
	e.dedupWin.MarkBatch(markedIPs)
}

// sweep removes expired bans from Cloudflare and the local banned map.
// Only entries with a non-empty cfItemID (i.e. synced from CF) are eligible.
//
// Two-phase cleanup:
//
//	Phase 1 — collect expired entries (cfItemID + IP) under RLock (read-only).
//	Phase 2 — call RemoveItems API.
//	Phase 3 — delete from banned map only on success.
//
// This prevents the "lost ban" scenario: if the API call fails, the entry
// stays in the map and will be retried on the next sweep cycle.
func (e *CloudflareExecutor) sweep(ctx context.Context) {
	type expiredEntry struct {
		itemID string
		ip     string
	}

	e.mu.RLock()
	expired := make([]expiredEntry, 0, len(e.banned))
	now := time.Now()
	for ip, rec := range e.banned {
		if rec.cfItemID != "" && now.Sub(rec.addedAt) > e.cfg.TTL {
			expired = append(expired, expiredEntry{itemID: rec.cfItemID, ip: ip})
		}
	}
	e.mu.RUnlock()

	if len(expired) == 0 {
		return
	}

	// Build the list of cfItemIDs for the API call.
	itemIDs := make([]string, len(expired))
	for i, entry := range expired {
		itemIDs[i] = entry.itemID
	}

	if !e.waitForPendingOp(ctx) {
		return
	}

	opID, err := e.doWithRetry(ctx, func() (string, error) {
		return e.client.RemoveItems(ctx, e.listID, itemIDs)
	})
	if err != nil {
		e.stats.errors.Add(int64(len(expired)))
		return
	}

	if opID != "" {
		e.pendingMu.Lock()
		e.pendingOpID = opID
		e.pendingOpAt = time.Now()
		e.pendingMu.Unlock()
	}

	// Phase 3: remove from banned map only on successful API call.
	e.mu.Lock()
	for _, entry := range expired {
		delete(e.banned, entry.ip)
	}
	e.mu.Unlock()

	e.stats.swept.Add(int64(len(expired))) // M7: swept — separate counter for removed bans
}

func (e *CloudflareExecutor) Stats() plugin.ExecutorStats {
	return plugin.ExecutorStats{
		Executed: e.stats.executed.Load(),
		Skipped:  e.stats.skipped.Load(),
		Errors:   e.stats.errors.Load(),
		Swept:    e.stats.swept.Load(),
	}
}

func (e *CloudflareExecutor) meetsMinLevel(level string) bool {
	if _, ok := levelOrder[level]; !ok {
		return false
	}
	return levelOrder[level] >= levelOrder[e.cfg.MinLevel]
}

func (e *CloudflareExecutor) isDuplicate(ip string) bool {
	// Step 1: dedup window (pure Contains, no side-effect).
	// Mark is called separately from flush() after a successful AddItems —
	// this is flaky-safe: a CF API error does not poison the window.
	if e.dedupWin.Contains(ip) {
		return true
	}

	// Step 2: fallback to banned-map for backward compatibility
	// (when DedupWindow is not configured or has not yet been populated).
	// RLock is sufficient — isDuplicate is a read-only check.
	e.mu.RLock()
	defer e.mu.RUnlock()
	_, exists := e.banned[ip]
	return exists
}

func (e *CloudflareExecutor) buildComment() string {
	base := fmt.Sprintf("sentinel-%s", e.instanceID)
	if e.cfg.CommentExtra == "" {
		return base
	}
	return base + " " + e.cfg.CommentExtra
}

func LoadInstanceID(cfg *Config) string {
	if cfg.InstanceID != "" {
		return cfg.InstanceID
	}
	data, err := os.ReadFile("/var/lib/arxsentinel/instance.id")
	if err == nil {
		return strings.TrimSpace(string(data))
	}
	data, err = os.ReadFile("/etc/machine-id")
	if err == nil {
		id := strings.TrimSpace(string(data))
		return id
	}
	id := genUUID()
	return id
}

func genUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "unknown"
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(b[0:4]),
		hex.EncodeToString(b[4:6]),
		hex.EncodeToString(b[6:8]),
		hex.EncodeToString(b[8:10]),
		hex.EncodeToString(b[10:16]),
	)
}
