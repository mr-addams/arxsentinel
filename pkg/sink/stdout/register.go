// ====== Module: pkg/sink/stdout — Registration ======
//   Self-registering sink plugin entry point.

package stdout

import (
	"context"

	"github.com/mr-addams/arxsentinel/pkg/plugin"
	pkgsink "github.com/mr-addams/arxsentinel/pkg/sink"
)

// init registers the "stdout" sink with the global sink registry.
func init() {
	pkgsink.Register("stdout", func(_ context.Context, cfg pkgsink.SinkConfig) (plugin.Sink, error) {
		// ctx не используется: NewStdoutSink — pure-alloc, без I/O.
		return NewStdoutSink(cfg.Format)
	})
	pkgsink.RegisterManifest("stdout", (&StdoutSink{}).Manifest())
}
