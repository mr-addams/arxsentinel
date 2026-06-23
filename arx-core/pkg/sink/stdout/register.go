// ====== Module: pkg/sink/stdout — Registration ======
//   Self-registering sink plugin entry point.
//
//   Phase 2.2 (Flow 083 / RESOLVED-Z12): the sink expects a Formatter on
//   SinkConfig (filled by the product-side pipeline assembly). The core
//   stays free of product knowledge — only the Formatter interface from
//   pkg/sink/format crosses the boundary, not any concrete impl.

package stdout

import (
	"context"

	"github.com/mr-addams/arx-core/pkg/plugin"
	pkgsink "github.com/mr-addams/arx-core/pkg/sink"
)

func init() {
	pkgsink.Register("stdout", func(_ context.Context, cfg pkgsink.SinkConfig) (plugin.Sink, error) {
		return NewStdoutSink(cfg.Formatter)
	})
	pkgsink.RegisterManifest("stdout", (&StdoutSink{}).Manifest())
}