// ====== Module: opnsense — registration ===========================================
//   Self-registration of OpnsenseExecutor in pkg/executor registry.
//   Uses init() to register the executor factory, enabling discovery
//   without a central import list.
//
//   FLOW 096 TASK 5 — Registration:
//     Mirrors the openwrt register.go pattern (Flow 095 Task 3.2):
//     same factory signature, same init() shape, same Register +
//     RegisterManifest pair. The factory is a thin wrapper that forwards
//     cfg + log to NewOpnsenseExecutor (implemented in Task 4).

package opnsense

import (
	"github.com/mr-addams/arx-core/pkg/executor"
	"github.com/mr-addams/arx-core/pkg/logger"
	"github.com/mr-addams/arx-core/pkg/plugin"
)

func init() {
	executor.Register("opnsense", newOpnsenseFactory)
	executor.RegisterManifest("opnsense", (&OpnsenseExecutor{}).Manifest())
}

// newOpnsenseFactory creates an OpnsenseExecutor from an ExecutorConfig.
// Mirrors the openwrt equivalent (Flow 095 Task 3.2 closure): cfg.Config
// is forwarded as-is to the constructor, and `log` is the operational
// logger injected by the registry Build() pipeline. A nil log is replaced
// with logger.Nop inside NewOpnsenseExecutor (Flow 072 Decision 2).
//
// Note: cfg.Config is a map[string]any — a reference type in Go.
// The assignment only copies the map header (pointer, length, hash seed),
// not the underlying data. Since cfg.Config is treated as read-only
// after this point, sharing the underlying map is safe.
func newOpnsenseFactory(cfg executor.ExecutorConfig, log logger.Logger) (plugin.Executor, error) {
	return NewOpnsenseExecutor(cfg, log)
}
