// ========================== Package nginx ==========================
//   Self-registration of NginxExecutor in pkg/executor registry.
//   Uses init() to register the executor factory, enabling discovery
//   without a central import list — same pattern as pkg/executor/cloudflare.
//
//   FLOW 073 TASK 1.3.1 — Configuration decoupling:
//     - factory no longer builds a config.ExecutorItem; NewNginxExecutor
//       now accepts executor.ExecutorConfig directly (Phase 1.3 prep for ADR-002).
//     - logger is forwarded from Build() (was logger.Nop before F1 closure).

package nginx

import (
	"github.com/mr-addams/arx-core/pkg/executor"
	"github.com/mr-addams/arx-core/pkg/logger"
	"github.com/mr-addams/arx-core/pkg/plugin"
)

func init() {
	executor.Register("nginx", newNginxFactory)
	executor.RegisterManifest("nginx", (&NginxExecutor{}).Manifest())
}

// newNginxFactory creates an NginxExecutor from an ExecutorConfig.
// Flow 073 / Task 1.3.1: cfg.Config is forwarded as-is — NewNginxExecutor
// now takes executor.ExecutorConfig directly, so the wrapper into
// config.ExecutorItem (deprecated in Phase 1.3) is gone. The `log` argument
// is what Build() forwards from cmd/arxsentinel (utils.AsLogger()) —
// pre-1.3 this branch silently used logger.Nop, swallowing EXECUTOR-tag
// diagnostics (F1 closure: this is now a real bridge).
//
// Note: cfg.Config is a map[string]any — a reference type in Go.
// The assignment only copies the map header (pointer, length, hash seed),
// not the underlying data. Since cfg.Config is treated as read-only
// after this point, sharing the underlying map is safe.
func newNginxFactory(cfg executor.ExecutorConfig, log logger.Logger) (plugin.Executor, error) {
	return NewNginxExecutor(cfg, log)
}
