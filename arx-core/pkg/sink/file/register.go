// ====== Module: pkg/sink/file — Registration ======
//   Self-registering sink plugin entry point.
//   Called from: main.go → plugin registration during init().
//
//   Phase 2.2 (Flow 083 / RESOLVED-Z12): the sink expects a Formatter on
//   SinkConfig (filled by the product-side pipeline assembly). The core
//   stays free of product knowledge — only the Formatter interface from
//   pkg/sink/format crosses the boundary, not any concrete impl.

package file

import (
	"context"

	"github.com/mr-addams/arx-core/pkg/plugin"
	pkgsink "github.com/mr-addams/arx-core/pkg/sink"
)

// init registers the "file" sink with the global sink registry.
// Blocking: runs at package import time during program initialization.
func init() {
	pkgsink.Register("file", func(_ context.Context, cfg pkgsink.SinkConfig) (plugin.Sink, error) {
		return NewFileSink(cfg.Path, cfg.Formatter)
	})
	pkgsink.RegisterManifest("file", (&FileSink{}).Manifest())
}