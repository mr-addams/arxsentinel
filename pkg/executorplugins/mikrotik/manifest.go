// ====== Module: mikrotik — manifest ===============================================
//
//	Plugin identity and data contract for the MikroTik executor.
//	Declares: Role=Executor, Input=TypeScoredEvent, Output=TypeNone.
package mikrotik

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/mr-addams/arx-core/pkg/dedup"
	"github.com/mr-addams/arx-core/pkg/logger"
	"github.com/mr-addams/arx-core/pkg/plugin"
)

type MikroTikExecutor struct {
	name   string
	cfg    Config
	client Client
	mu     sync.Mutex
	banned map[string]banRecord
	stats  struct {
		executed atomic.Int64
		skipped  atomic.Int64
		errors   atomic.Int64
		swept    atomic.Int64 // monotonic counter for bans removed by sweep
	}

	// logger is the operational logger injected by the caller. Replaces the
	// pre-1.2 global utils.Log dependency — see Flow 072 Decision 2. Always
	// non-nil in practice (constructor replaces nil with logger.Nop).
	logger logger.Logger

	// dedupWin — deduplication window layered on top of the banned map.
	// TTL = cfg.DedupWindow: 0 → disabled, > 0 → forbids a second
	// Add for the same IP within TTL after a successful add.
	dedupWin *dedup.Window
}

type banRecord struct {
	id      string
	addedAt time.Time
}

// expiredEntry carries a sweep candidate (both RouterOS entry ID and IP address)
// from the lock-protected collection phase to the API deletion phase.
type expiredEntry struct {
	id string
	ip string
}

func (e *MikroTikExecutor) Name() string {
	if e.cfg.ListName != "" {
		return e.cfg.ListName
	}
	return "mikrotik"
}

func (e *MikroTikExecutor) Type() string {
	return "mikrotik"
}

func (e *MikroTikExecutor) Manifest() plugin.Manifest {
	return plugin.Manifest{
		PluginID:      "mikrotik",
		PluginVersion: "1.0.0",
		Role:          plugin.RoleExecutor,
		InputType:     plugin.TypeScoredEvent,
		OutputType:    plugin.TypeNone,
		Tags:          []string{"routeros-v7", "v7.18.2+", "rest-api", "embedded-capable"},
	}
}
