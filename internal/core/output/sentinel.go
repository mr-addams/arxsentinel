package output

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/mr-addams/arxsentinel/pkg/executor"
	"github.com/mr-addams/arxsentinel/pkg/executor/queue"
	"github.com/mr-addams/arxsentinel/pkg/plugin"
	pkgsink "github.com/mr-addams/arxsentinel/pkg/sink"
)

type SentinelThreatSink struct {
	name    string
	q       queue.Queue
	dropped atomic.Int64
}

func NewSentinelThreatSink(name string, bufferSize int) (*SentinelThreatSink, error) {
	if name == "" {
		return nil, fmt.Errorf("sentinel-threat sink: name is required")
	}
	q, err := executor.RegisterSink(name, bufferSize)
	if err != nil {
		return nil, fmt.Errorf("sentinel-threat sink %q: %w", name, err)
	}
	return &SentinelThreatSink{name: name, q: q}, nil
}

func (s *SentinelThreatSink) Name() string {
	return "sentinel-threat:" + s.name
}

func (s *SentinelThreatSink) Write(event plugin.ThreatEvent) error {
	if err := s.q.Push(context.Background(), event); err != nil {
		if errors.Is(err, queue.ErrQueueFull) {
			s.dropped.Add(1)
			return nil
		}
		return err
	}
	return nil
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
