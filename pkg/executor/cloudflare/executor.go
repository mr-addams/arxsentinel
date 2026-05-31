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
	"github.com/mr-addams/arxsentinel/pkg/plugin"
)

type threatLevel int

const (
	levelInfo   threatLevel = iota
	levelWarn
	levelThreat
)

var levelOrder = map[string]threatLevel{
	"INFO":   levelInfo,
	"WARN":   levelWarn,
	"THREAT": levelThreat,
}

const defaultSweepInterval = 15 * time.Minute

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

	mu     sync.Mutex
	banned map[string]banRecord
	stats  struct {
		executed atomic.Int64
		skipped  atomic.Int64
		errors   atomic.Int64
	}
}

func NewCloudflareExecutor(cfg config.ExecutorItem) (plugin.Executor, error) {
	parsed, err := parseConfig(cfg.Config)
	if err != nil {
		return nil, fmt.Errorf("cloudflare: new executor: %w", err)
	}

	if parsed.TTL <= 0 {
		return nil, fmt.Errorf("cloudflare: new executor: TTL must be positive, got %v", parsed.TTL)
	}

	client := NewHTTPCFClient(parsed.AccountID, parsed.APIToken)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	listID, err := client.FindOrCreateList(ctx, parsed.ListName)
	if err != nil {
		return nil, fmt.Errorf("cloudflare: new executor: %w", err)
	}

	exec := &CloudflareExecutor{
		name:       cfg.Name,
		execType:   "cloudflare",
		cfg:        parsed,
		client:     client,
		listID:     listID,
		banned:     make(map[string]banRecord),
		instanceID: LoadInstanceID(&parsed),
	}

	syncCtx, syncCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer syncCancel()
	if err := exec.syncExisting(syncCtx); err != nil {
		return nil, fmt.Errorf("cloudflare: new executor: %w", err)
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

// Run reads ThreatEvents from in, accumulates them in a buffer, and flushes
// to the Cloudflare API when batch_size is reached or flush_interval fires.
// Also runs a periodic sweep to remove expired bans.
func (e *CloudflareExecutor) Run(ctx context.Context, in <-chan plugin.ThreatEvent) error {
	buffer := make([]plugin.ThreatEvent, 0, e.cfg.BatchSize)
	ticker := time.NewTicker(e.cfg.FlushInterval)
	defer ticker.Stop()

	sweepInterval := e.cfg.TTL / 4
	if sweepInterval < defaultSweepInterval {
		sweepInterval = defaultSweepInterval
	}
	sweepTicker := time.NewTicker(sweepInterval)
	defer sweepTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			e.flush(ctx, buffer)
			e.sweep(ctx)
			return ctx.Err()
		case event, ok := <-in:
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

type cfBatchItem struct {
	IP      string `json:"ip"`
	Comment string `json:"comment"`
}

func (e *CloudflareExecutor) flush(ctx context.Context, events []plugin.ThreatEvent) {
	if len(events) == 0 {
		return
	}
	items := make([]CFBatchItem, len(events))
	for i, ev := range events {
		items[i] = CFBatchItem{
			IP:      ev.IP,
			Comment: e.buildComment(),
		}
	}
	if err := e.client.AddItems(ctx, e.listID, items); err != nil {
		e.stats.errors.Add(int64(len(events)))
		return
	}
	e.stats.executed.Add(int64(len(events)))

	e.mu.Lock()
	for _, ev := range events {
		e.banned[ev.IP] = banRecord{addedAt: time.Now(), addedByExecutor: true}
	}
	e.mu.Unlock()
}

func (e *CloudflareExecutor) sweep(ctx context.Context) {
	e.mu.Lock()
	expired := make([]string, 0)
	now := time.Now()
	for ip, rec := range e.banned {
		if rec.cfItemID != "" && now.Sub(rec.addedAt) > e.cfg.TTL {
			expired = append(expired, rec.cfItemID)
			delete(e.banned, ip)
		}
	}
	e.mu.Unlock()

	if len(expired) == 0 {
		return
	}

	if err := e.client.RemoveItems(ctx, e.listID, expired); err != nil {
		e.stats.errors.Add(int64(len(expired)))
		return
	}
	e.stats.executed.Add(-int64(len(expired)))
}

func (e *CloudflareExecutor) Stats() plugin.ExecutorStats {
	return plugin.ExecutorStats{
		Executed: e.stats.executed.Load(),
		Skipped:  e.stats.skipped.Load(),
		Errors:   e.stats.errors.Load(),
	}
}

func (e *CloudflareExecutor) meetsMinLevel(level string) bool {
	if _, ok := levelOrder[level]; !ok {
		return false
	}
	return levelOrder[level] >= levelOrder[e.cfg.MinLevel]
}

func (e *CloudflareExecutor) isDuplicate(ip string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, exists := e.banned[ip]
	return exists
}

func (e *CloudflareExecutor) buildComment() string {
	return fmt.Sprintf("sentinel-%s", e.instanceID)
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
