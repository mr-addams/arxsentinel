package file

import (
	"github.com/mr-addams/arxsentinel/pkg/plugin"
	pkgsink "github.com/mr-addams/arxsentinel/pkg/sink"
)

func init() {
	pkgsink.Register("file", func(cfg pkgsink.SinkConfig) (plugin.Sink, error) {
		return NewFileSink(cfg.Path, cfg.Format)
	})
	pkgsink.RegisterManifest("file", (&FileSink{}).Manifest())
}