// ====== Module: opnsense — manifest ===============================================
//
//	Plugin identity and data contract for the OPNsense executor.
//	Declares: Role=Executor, Input=TypeScoredEvent, Output=TypeNone.
//
//	WHAT IS HERE:
//	  OpnsenseExecutor struct (storage and collaborators needed by the
//	  Run / sweep logic in Task 4), Name/Type/Manifest methods. The
//	  Client interface (used by the `client` field below) is defined
//	  in client.go (Task 3) and resolved via same-package lookup.
//
//	WHAT IS NOT HERE:
//	  Run/sweep implementation (executor.go, Task 4), REST client
//	  (client.go, Task 3), registration (register.go, Task 5).
package opnsense

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/mr-addams/arx-core/pkg/dedup"
	"github.com/mr-addams/arx-core/pkg/logger"
	"github.com/mr-addams/arx-core/pkg/plugin"
)

// OpnsenseExecutor manages a single OPNsense alias (alias_util) and bans /
// unbans IPs over the firewall's REST API.
//
// Architectural model: mikrotik-style (see DECISIONS.md Decision 1) —
// independent point add/delete calls on every ScoredEvent plus an active
// TTL-sweep. There is no batching buffer, no flush_interval, no batch_size —
// the per-event add/delete is the natural model because OPNsense's
// alias_util endpoints apply changes immediately (pfctl table updates
// per-call). The sweep timer is computed in executor.go (Task 4) as
// `TTL/4` with a 15-minute floor; it is intentionally NOT a config field.
//
// Struct fields below are the storage and collaborators required by the
// Run / sweep logic implemented in Task 4. Their concrete usage (banned
// map, dedup window, sweep ticker, etc.) is intentionally left for the
// next task — only Name/Type/Manifest are wired up here so the package
// compiles cleanly.
type OpnsenseExecutor struct {
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
	// TTL = cfg.DedupWindow: 0 → disabled, > 0 → blocks a repeat
	// alias_util/add for the same IP within TTL after a successful ban.
	dedupWin *dedup.Window
}

// banRecord carries the local TTL tracking for a banned IP.
//
// The `id` field present in the mikrotik equivalent is intentionally
// absent: RouterOS address-list items carry an item-id used to address
// a specific entry, whereas OPNsense alias_util/add and
// alias_util/delete operate on the IP value itself — there is no
// per-entry identifier on the wire, the API takes only `{"address": "..."}`.
// The executor tracks the IP and addedAt locally so the sweep can decide
// when to issue a delete; tracking a fake local id would add code without
// changing any wire-format.
//
// expireAt is precomputed as addedAt + cfg.TTL at ban time so the sweep
// pass is a constant-time comparison rather than recomputing TTL on every
// tick for every record.
type banRecord struct {
	ip       string
	addedAt  time.Time
	expireAt time.Time
}

// Name returns the executor's display name. Mirrors the mikrotik/openwrt
// convention: prefer a user-facing identifier (AliasName) over the
// generic plugin type, falling back to "opnsense" when no alias has been
// configured yet (e.g. during dry-run construction before parseConfig).
func (e *OpnsenseExecutor) Name() string {
	if e.cfg.AliasName != "" {
		return e.cfg.AliasName
	}
	return "opnsense"
}

// Type returns the plugin type identifier — used for registry lookup and
// config dispatch (matches the "type: opnsense" YAML field).
func (e *OpnsenseExecutor) Type() string {
	return "opnsense"
}

// Manifest declares the plugin's data contract: it consumes scored events
// from the detector stage and produces no further output (terminal action).
// Tags reflect the transport surface (REST/HTTPS, Basic Auth), the
// firewall stack (pf / FreeBSD), and the OPNsense feature used
// (alias_util with the type-restriction caveat from DECISIONS.md
// Decision 3).
func (e *OpnsenseExecutor) Manifest() plugin.Manifest {
	return plugin.Manifest{
		PluginID:      "opnsense",
		PluginVersion: "1.0.0",
		Role:          plugin.RoleExecutor,
		InputType:     plugin.TypeScoredEvent,
		OutputType:    plugin.TypeNone,
		Tags:          []string{"rest", "pf", "alias_util", "freebsd"},
	}
}
