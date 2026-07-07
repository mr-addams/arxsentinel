// ====== Module: openwrt — manifest ===============================================
//
//	Plugin identity and data contract for the OpenWrt executor.
//	Declares: Role=Executor, Input=TypeScoredEvent, Output=TypeNone.
//
//	WHAT IS HERE:
//	  OpenwrtExecutor struct (storage and collaborators needed by the
//	  Run / flush / sweep logic in Task 3.1), Name/Type/Manifest methods.
//
//	WHAT IS NOT HERE:
//	  Run/flush implementation (executor.go, Task 3.1), ubus client
//	  (client.go, Task 2.2), registration (register.go, Task 3.2).
package openwrt

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/mr-addams/arx-core/pkg/dedup"
	"github.com/mr-addams/arx-core/pkg/logger"
	"github.com/mr-addams/arx-core/pkg/plugin"
)

// OpenwrtExecutor manages an nftables ipset on a remote OpenWrt router via
// ubus (uhttpd-mod-ubus). Receives ScoredEvents, batches them, and flushes
// through UCI edits plus a single rc.init(reload) per cycle (DECISIONS.md
// Decision 3, Decision 4).
//
// Struct fields below are the storage and collaborators required by the
// Run / flush / sweep logic implemented in Task 3.1. Their concrete usage
// (banned map, dedup window, client, etc.) is intentionally left for the
// next task — only Name/Type/Manifest are wired up here so the package
// compiles and registers cleanly.
type OpenwrtExecutor struct {
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

	// logger is the operational logger injected by the caller. Replaces
	// the pre-1.2 global utils.Log dependency (see Flow 072 Decision 2).
	// Always non-nil in practice (constructor replaces nil with logger.Nop).
	logger logger.Logger

	// dedupWin is a dedup window layered on top of the banned map.
	// TTL = cfg.DedupWindow: 0 → disabled, > 0 → blocks a repeat add_list
	// for the same IP within TTL after a successful add.
	dedupWin *dedup.Window
}

// banRecord mirrors the mikrotik equivalent — local TTL tracking for each
// banned IP. The executor relies on this map rather than nftables-native
// timeouts because fw4 reload re-creates the nftables ruleset from UCI on
// every apply, which would reset all per-entry timers
// (DECISIONS.md Decision 4).
//
// The `id` field from the mikrotik equivalent is intentionally absent:
// RouterOS address-list items carry an item-id used to address a specific
// entry, whereas an OpenWrt UCI ipset `list entry '<ip>'` is a bare string
// with no per-entry identifier — deletions are issued by value
// (`uci.del_list` with the full list), not by item-id. Tracking a fake
// local id would add code without changing any wire-format.
type banRecord struct {
	ip       string
	addedAt  time.Time
	expireAt time.Time
}

// Name returns the executor's display name. Mirrors the mikrotik convention:
// prefer a user-facing identifier (IPSetName) over the generic plugin type.
func (e *OpenwrtExecutor) Name() string {
	if e.cfg.IPSetName != "" {
		return e.cfg.IPSetName
	}
	return "openwrt"
}

// Type returns the plugin type identifier — used for registry lookup and
// config dispatch (matches the "type: openwrt" YAML field).
func (e *OpenwrtExecutor) Type() string {
	return "openwrt"
}

// Manifest declares the plugin's data contract: it consumes scored events
// from the detector stage and produces no further output (terminal action).
// Tags reflect the transport surface (ubus/uhttpd) and the firewall stack
// (fw4 / nftables / UCI) the plugin targets.
func (e *OpenwrtExecutor) Manifest() plugin.Manifest {
	return plugin.Manifest{
		PluginID:      "openwrt",
		PluginVersion: "1.0.0",
		Role:          plugin.RoleExecutor,
		InputType:     plugin.TypeScoredEvent,
		OutputType:    plugin.TypeNone,
		Tags:          []string{"ubus", "fw4", "nftables", "uci"},
	}
}
