// ========================== Package cloudflare ==========================
//   Self-registration of CloudflareExecutor in pkg/executor registry.
//   Uses init() to register the executor factory, enabling discovery
//   without a central import list — same pattern as pkg/detector.

package cloudflare

import (
	"github.com/mr-addams/arxsentinel/internal/sys/config"
	"github.com/mr-addams/arxsentinel/pkg/executor"
	"github.com/mr-addams/arxsentinel/pkg/plugin"
)

func init() {
	executor.Register("cloudflare", newCloudflareFactory)
}

// newCloudflareFactory creates a CloudflareExecutor from an ExecutorConfig.
// It wraps the config into a config.ExecutorItem and delegates to
// NewCloudflareExecutor.
//
// Note: cfg.Config is a map[string]any — a reference type in Go.
// The assignment only copies the map header (pointer, length, hash seed),
// not the underlying data. Since cfg.Config is treated as read-only
// after this point, sharing the underlying map is safe.
func newCloudflareFactory(cfg executor.ExecutorConfig) (plugin.Executor, error) {
	item := config.ExecutorItem{
		Name:   cfg.Name,
		Type:   cfg.Type,
		Config: cfg.Config,
	}
	return NewCloudflareExecutor(item)
}
