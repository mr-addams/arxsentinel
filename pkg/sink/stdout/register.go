package stdout

import (
	"github.com/mr-addams/arxsentinel/pkg/plugin"
	pkgsink "github.com/mr-addams/arxsentinel/pkg/sink"
)

func init() {
	pkgsink.Register("stdout", func(cfg pkgsink.SinkConfig) (plugin.Sink, error) {
		return NewStdoutSink(cfg.Format)
	})
	pkgsink.RegisterManifest("stdout", (&StdoutSink{}).Manifest())
}