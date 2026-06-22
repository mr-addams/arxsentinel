// ====== Module: HTTP Source ======
// Accepts log events via HTTP/HTTPS in various cloud formats.
// Supports push (webhook) and pull (polling) modes with protocol-specific adapters.

package http

import (
	"context"
	"fmt"
	"sync/atomic"

	"github.com/mr-addams/arx-core/pkg/plugin"
	pkgsource "github.com/mr-addams/arx-core/pkg/source"
	"github.com/mr-addams/arx-core/pkg/source/http/adapters"
)

// sourceCounters holds runtime statistics for the HTTP source.
// These are atomically updated by multiple goroutines.
type sourceCounters struct {
	linesRead   int64 // YAML: linesRead — total log lines received. Consumer: /metrics
	parseErrors int64 // YAML: parseErrors — failed to parse envelope. Consumer: /metrics
	dropped     int64 // YAML: dropped — dropped due to body size limit. Consumer: /metrics
}

// HTTPSource implements plugin.Source for HTTP log ingestion.
// Manages both push (webhook) and pull (polling) HTTP server modes.
type HTTPSource struct {
	name     string                       // YAML: name — human-readable source name. Consumer: /metrics
	cfg      *parsedConfig                // YAML: addr, protocol, mode — runtime config. Consumer: runPush/runPull
	par      pkgsource.LineParser         // YAML: parser — parses raw log lines. Consumer: runPush/runPull
	logFn    func(string, string, string) // YAML: logFn — structured logger function. Consumer: runPush/runPull
	counters sourceCounters               // YAML: counters — runtime statistics. Consumer: Stats()
}

// New creates a new HTTPSource from configuration.
// Returns error if protocol is unsupported or parser is nil.
// Called from: pkgsource.Register() during plugin initialization.
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

// Name returns the source identifier. Non-blocking.
func (s *HTTPSource) Name() string {
	return "http"
}

// Close releases resources. Non-blocking.
func (s *HTTPSource) Close() error {
	return nil
}

// Stats returns current counters for metrics endpoint. Non-blocking.
func (s *HTTPSource) Stats() plugin.SourceStats {
	return plugin.SourceStats{
		LinesRead:   atomic.LoadInt64(&s.counters.linesRead),
		ParseErrors: atomic.LoadInt64(&s.counters.parseErrors),
		Dropped:     atomic.LoadInt64(&s.counters.dropped),
	}
}

// Manifest declares plugin capabilities to the registry. Non-blocking.
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

// Run starts the HTTP source — either push (webhook) or pull (polling).
// Routes to runPush or runPull based on mode configuration.
// Called from: plugin exec loop. Non-blocking.
func (s *HTTPSource) Run(ctx context.Context, out chan<- *plugin.LogEntry) error {
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

// init registers this plugin with the source registry.
// Called from: plugin exec loop during initialization. Non-blocking.
func init() {
	pkgsource.Register("http", func(cfg pkgsource.InputConfig, opts pkgsource.BuildOptions) (plugin.Source, error) {
		return New(cfg, opts.Parser, opts.LogFn)
	})
	pkgsource.RegisterManifest("http", (&HTTPSource{}).Manifest())
}
