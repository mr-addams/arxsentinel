// ====== Module: pkg/sink/file — Registration ======
//   Self-registering sink plugin entry point.
//   Called from: main.go → plugin registration during init().

package file

import (
	"github.com/mr-addams/arxsentinel/pkg/plugin"
	pkgsink "github.com/mr-addams/arxsentinel/pkg/sink"
)

// init registers the "file" sink with the global sink registry.
// Blocking: runs at package import time during program initialization.
func init() {
	pkgsink.Register("file", func(cfg pkgsink.SinkConfig) (plugin.Sink, error) {
		return NewFileSink(cfg.Path, cfg.Format)
	})
	pkgsink.RegisterManifest("file", (&FileSink{}).Manifest())
}