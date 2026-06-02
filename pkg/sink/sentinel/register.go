package sentinel

import (
	"github.com/mr-addams/arxsentinel/pkg/plugin"
	pkgsink "github.com/mr-addams/arxsentinel/pkg/sink"
)

func init() {
	pkgsink.Register("sentinel-threat", func(cfg pkgsink.SinkConfig) (plugin.Sink, error) {
		return NewSentinelThreatSink(cfg.Name, 0)
	})
	pkgsink.RegisterManifest("sentinel-threat", (&SentinelThreatSink{}).Manifest())
}