// ====== Module: openwrt — registration ===========================================
//   Self-registration of OpenwrtExecutor in pkg/executor registry.
//   Uses init() to register the executor factory, enabling discovery
//   without a central import list.
//
//   FLOW 095 TASK 3.2 — Registration:
//     Mirrors the mikrotik register.go pattern: same factory signature,
//     same init() shape, same Register + RegisterManifest pair. The factory
//     is a thin wrapper that forwards cfg + log to NewOpenwrtExecutor
//     (implemented in Task 3.1).

package openwrt

import (
	"github.com/mr-addams/arx-core/pkg/executor"
	"github.com/mr-addams/arx-core/pkg/logger"
	"github.com/mr-addams/arx-core/pkg/plugin"
)

func init() {
	executor.Register("openwrt", newOpenwrtFactory)
	executor.RegisterManifest("openwrt", (&OpenwrtExecutor{}).Manifest())
}

// newOpenwrtFactory creates an OpenwrtExecutor from an ExecutorConfig.
// Mirrors the mikrotik equivalent (Flow 073 Task 1.3.1 closure): cfg.Config
// is forwarded as-is to the constructor, and `log` is the operational
// logger injected by the registry Build() pipeline. A nil log is replaced
// with logger.Nop inside NewOpenwrtExecutor (Flow 072 Decision 2).
//
// Note: cfg.Config is a map[string]any — a reference type in Go.
// The assignment only copies the map header (pointer, length, hash seed),
// not the underlying data. Since cfg.Config is treated as read-only
// after this point, sharing the underlying map is safe.
func newOpenwrtFactory(cfg executor.ExecutorConfig, log logger.Logger) (plugin.Executor, error) {
	return NewOpenwrtExecutor(cfg, log)
}
