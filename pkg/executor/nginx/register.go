// ========================== Package nginx ==========================
//   Self-registration of NginxExecutor in pkg/executor registry.
//   Uses init() to register the executor factory, enabling discovery
//   without a central import list — same pattern as pkg/executor/cloudflare.

package nginx

import (
	"github.com/mr-addams/arxsentinel/internal/sys/config"
	"github.com/mr-addams/arxsentinel/pkg/executor"
	"github.com/mr-addams/arxsentinel/pkg/plugin"
)

func init() {
	executor.Register("nginx", newNginxFactory)
	executor.RegisterManifest("nginx", (&NginxExecutor{}).Manifest())
}

// newNginxFactory creates an NginxExecutor from an ExecutorConfig.
// It wraps the config into a config.ExecutorItem and delegates to
// NewNginxExecutor.
func newNginxFactory(cfg executor.ExecutorConfig) (plugin.Executor, error) {
	item := config.ExecutorItem{
		Name:   cfg.Name,
		Type:   cfg.Type,
		Config: cfg.Config,
	}
	return NewNginxExecutor(item)
}
