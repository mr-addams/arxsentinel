// ========================== Package nginx ==========================
//   Self-registration of NginxExecutor in pkg/executor registry.
//   Uses init() to register the executor factory, enabling discovery
//   without a central import list — same pattern as pkg/executor/cloudflare.

package nginx

import (
	"github.com/mr-addams/arxsentinel/internal/sys/config"
	"github.com/mr-addams/arxsentinel/pkg/executor"
	"github.com/mr-addams/arxsentinel/pkg/logger"
	"github.com/mr-addams/arxsentinel/pkg/plugin"
)

func init() {
	executor.Register("nginx", newNginxFactory)
	executor.RegisterManifest("nginx", (&NginxExecutor{}).Manifest())
}

// newNginxFactory creates an NginxExecutor from an ExecutorConfig.
// It wraps the config into a config.ExecutorItem and delegates to
// NewNginxExecutor.
//
// Note: cfg.Config is a map[string]any — a reference type in Go.
// The assignment only copies the map header (pointer, length, hash seed),
// not the underlying data. Since cfg.Config is treated as read-only
// after this point, sharing the underlying map is safe.
//
// The registry factory does not yet receive a logger from the caller
// (the Build() signature stays unchanged per Flow 072 Decision 7).
// pkg/logger.Nop is used here; cmd/arxsentinel will inject the real
// bridge in Task 1.2.7.
func newNginxFactory(cfg executor.ExecutorConfig) (plugin.Executor, error) {
	item := config.ExecutorItem{
		Name:   cfg.Name,
		Type:   cfg.Type,
		Config: cfg.Config,
	}
	return NewNginxExecutor(item, logger.Nop)
}
