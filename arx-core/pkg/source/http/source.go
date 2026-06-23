// ====== Module: HTTP Source ======
// Accepts log events via HTTP/HTTPS in various cloud formats.
// Supports push (webhook) and pull (polling) modes with protocol-specific adapters.
//
//   Phase 2.2 (Flow 083 / RESOLVED-Q9): emits *plugin.Event with parser-owned
//   LogEntry as Payload (built via WrapLogEntry).

package http

import (
	"context"
	"fmt"
	"sync/atomic"

	"github.com/mr-addams/arx-core/pkg/plugin"
	pkgsource "github.com/mr-addams/arx-core/pkg/source"
	"github.com/mr-addams/arx-core/pkg/source/http/adapters"
)

type sourceCounters struct {
	linesRead   int64
	parseErrors int64
	dropped     int64
}

// HTTPSource implements plugin.Source for HTTP log ingestion.
// Manages both push (webhook) and pull (polling) HTTP server modes.
type HTTPSource struct {
	name     string
	cfg      *parsedConfig
	par      pkgsource.LineParser
	logFn    func(string, string, string)
	counters sourceCounters
}

func New(cfg pkgsource.InputConfig, par pkgsource.LineParser, logFn func(string, string, string)) (*HTTPSource, error) {
	if par == nil {
		return nil, fmt.Errorf("http source: parser is required")
	}
	parsed, err := parseHTTPConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &HTTPSource{
		name:  "http",
		cfg:   parsed,
		par:   par,
		logFn: logFn,
	}, nil
}

func (s *HTTPSource) Name() string {
	return "http"
}

func (s *HTTPSource) Close() error {
	return nil
}

func (s *HTTPSource) Stats() plugin.SourceStats {
	return plugin.SourceStats{
		LinesRead:   atomic.LoadInt64(&s.counters.linesRead),
		ParseErrors: atomic.LoadInt64(&s.counters.parseErrors),
		Dropped:     atomic.LoadInt64(&s.counters.dropped),
	}
}

func (s *HTTPSource) Manifest() plugin.Manifest {
	return plugin.Manifest{
		PluginID:      "http",
		PluginVersion: "1.0.0",
		Role:          plugin.RoleSource,
		InputType:     plugin.TypeNone,
		OutputType:    plugin.TypeStructured,
		Tags:          []string{"http", "https", "push", "pull", "cloudflare", "firehose", "pubsub", "loki", "otlp", "azure", "splunk", "cloud"},
	}
}

func (s *HTTPSource) Run(ctx context.Context, out chan<- *plugin.Event) error {
	adapter, err := adapters.Build(s.cfg.proto, adapters.AdapterConfig{EnvelopeField: s.cfg.envelopeField})
	if err != nil {
		return err
	}
	if s.cfg.mode == "pull" {
		return runPull(ctx, s.cfg, adapter, out, s.par, s.logFn, &s.counters)
	}
	handler := buildPushHandler(s.cfg, adapter, out, s.par, s.logFn, s.cfg.maxBodyBytes, &s.counters)
	return runPush(ctx, s.cfg, handler)
}

func init() {
	pkgsource.Register("http", func(cfg pkgsource.InputConfig, opts pkgsource.BuildOptions) (plugin.Source, error) {
		return New(cfg, opts.Parser, opts.LogFn)
	})
	pkgsource.RegisterManifest("http", (&HTTPSource{}).Manifest())
}