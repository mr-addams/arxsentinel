// ====== Module: pkg/sink/sentinel — Registration ======
//   Self-registering sink plugin entry point.

package sentinel

import (
	"context"

	"github.com/mr-addams/arx-core/pkg/plugin"
	pkgsink "github.com/mr-addams/arx-core/pkg/sink"
)

// init registers the "sentinel-threat" sink with the global sink registry.
func init() {
	pkgsink.Register("sentinel-threat", func(_ context.Context, cfg pkgsink.SinkConfig) (plugin.Sink, error) {
		// ctx не используется: NewSentinelThreatSink не делает blocking init.
		// Принимается через Factory-сигнатуру для совместимости с buildSinks.
		return NewSentinelThreatSink(cfg.Name, 0)
	})
	pkgsink.RegisterManifest("sentinel-threat", (&SentinelThreatSink{}).Manifest())
}
