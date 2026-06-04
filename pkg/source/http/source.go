package http

import (
	"context"
	"fmt"
	"sync/atomic"

	"github.com/mr-addams/arxsentinel/pkg/plugin"
	pkgsource "github.com/mr-addams/arxsentinel/pkg/source"
	"github.com/mr-addams/arxsentinel/pkg/source/http/adapters"
)

type sourceCounters struct {
	linesRead   int64
	parseErrors int64
	dropped     int64
}

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
		name: "http",
		cfg:  parsed,
		par:  par,
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

func buildAdapter(proto protocol, cfg *parsedConfig) adapters.Adapter {
	switch proto {
	case protocolPlain:
		return adapters.New("", false)
	case protocolNDJSON:
		return adapters.New(cfg.envelopeField, true)
	case protocolCloudflare:
		return &adapters.CloudflareAdapter{}
	case protocolFirehose:
		return &adapters.FirehoseAdapter{}
	case protocolPubSub:
		return &adapters.PubSubAdapter{}
	case protocolLoki:
		return &adapters.LokiAdapter{}
	case protocolOTLP:
		return &adapters.OTLPAdapter{}
	case protocolAzure:
		return &adapters.AzureAdapter{}
	case protocolSplunk:
		return &adapters.SplunkAdapter{}
	default:
		panic("http source: unknown protocol")
	}
}

func (s *HTTPSource) Run(ctx context.Context, out chan<- *plugin.LogEntry) error {
	adapter := buildAdapter(s.cfg.proto, s.cfg)
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