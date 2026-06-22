// ====== Module: pkg/sink/file — Registration ======
//   Self-registering sink plugin entry point.
//   Called from: main.go → plugin registration during init().

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
		// ctx не используется: NewFileSink делает только stat() — неблокирующий.
		return NewFileSink(cfg.Path, cfg.Format)
	})
	pkgsink.RegisterManifest("file", (&FileSink{}).Manifest())
}
