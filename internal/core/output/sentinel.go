package output

import (
	"fmt"
	"sync/atomic"

	"github.com/mr-addams/arxsentinel/pkg/executor"
	"github.com/mr-addams/arxsentinel/pkg/plugin"
	pkgsink "github.com/mr-addams/arxsentinel/pkg/sink"
)

type SentinelThreatSink struct {
	name    string
	ch      chan<- plugin.ThreatEvent
	dropped atomic.Int64
}

func NewSentinelThreatSink(name string, bufferSize int) (*SentinelThreatSink, error) {
	if name == "" {
		return nil, fmt.Errorf("sentinel-threat sink: name is required")
	}
	ch, err := executor.RegisterSink(name, bufferSize)
	if err != nil {
		return nil, fmt.Errorf("sentinel-threat sink %q: %w", name, err)
	}
	return &SentinelThreatSink{name: name, ch: ch}, nil
}

func (s *SentinelThreatSink) Name() string {
	return "sentinel-threat:" + s.name
}

func (s *SentinelThreatSink) Write(event plugin.ThreatEvent) error {
	select {
	case s.ch <- event:
		return nil
	default:
		s.dropped.Add(1)
		return fmt.Errorf("sentinel-threat sink %s: channel full, dropping event", s.name)
	}
}

func (s *SentinelThreatSink) Close() error {
	executor.Unregister(s.name)
	return nil
}

func (s *SentinelThreatSink) Stats() plugin.SinkStats {
	return plugin.SinkStats{
		Dropped: s.dropped.Load(),
	}
}

func init() {
	pkgsink.Register("sentinel-threat", func(cfg pkgsink.SinkConfig) (plugin.Sink, error) {
		return NewSentinelThreatSink(cfg.Name, 0)
	})
}
