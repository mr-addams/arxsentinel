// ========================== Package mikrotik ==========================
//   Self-registration of MikroTikExecutor in pkg/executor registry.
//   Uses init() to register the executor factory, enabling discovery
//   without a central import list — same pattern as pkg/executor/cloudflare.

package mikrotik

import (
	"github.com/mr-addams/arxsentinel/internal/sys/config"
	"github.com/mr-addams/arxsentinel/pkg/executor"
	"github.com/mr-addams/arxsentinel/pkg/plugin"
)

func init() {
	executor.Register("mikrotik", newMikroTikFactory)
	executor.RegisterManifest("mikrotik", (&MikroTikExecutor{}).Manifest())
}

// newMikroTikFactory creates a MikroTikExecutor from an ExecutorConfig.
func newMikroTikFactory(cfg executor.ExecutorConfig) (plugin.Executor, error) {
	item := config.ExecutorItem{
		Name:   cfg.Name,
		Type:   cfg.Type,
		Config: cfg.Config,
	}
	return NewMikroTikExecutor(item)
}