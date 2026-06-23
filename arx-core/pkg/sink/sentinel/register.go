// ====== Module: pkg/sink/sentinel — Registration ======
//   Self-registering sink plugin entry point.
//
//   Phase 2.2 (Flow 083 / RESOLVED-Z12): the sink expects a Formatter on
//   SinkConfig (filled by the product-side pipeline assembly).

package sentinel

import (
	"context"

	"github.com/mr-addams/arx-core/pkg/plugin"
	pkgsink "github.com/mr-addams/arx-core/pkg/sink"
)

func init() {
	pkgsink.Register("sentinel-threat", func(_ context.Context, cfg pkgsink.SinkConfig) (plugin.Sink, error) {
		return NewSentinelThreatSink(cfg.Name, cfg.Formatter, 0)
	})
	pkgsink.RegisterManifest("sentinel-threat", (&SentinelThreatSink{}).Manifest())
}