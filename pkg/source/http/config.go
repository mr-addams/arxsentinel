// ====== Module: HTTP Configuration ======
// Parses and validates HTTP source configuration from YAML.
// Handles protocol selection, URL parsing, TLS setup, and defaults.

package http

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	pkgsource "github.com/mr-addams/arxsentinel/pkg/source"
)

// protocol represents supported HTTP log ingestion protocols.
// Used in parsedConfig.proto field to route to appropriate adapter.
type protocol int

const (
	protocolPlain      protocol = iota // plain: raw newline-delimited logs
	protocolNDJSON                     // ndjson: newline-delimited JSON with optional envelope field
	protocolCloudflare                 // cloudflare: Cloudflare Logpull format
	protocolFirehose                   // firehose: AWS Kinesis Firehose format
	protocolPubSub                     // pubsub: GCP Pub/Sub push format
	protocolLoki                       // loki: Grafana Loki push API format
	protocolOTLP                       // otlp: OpenTelemetry Protocol format
	protocolAzure                      // azure: Azure Monitor Data Collector API format
	protocolSplunk                     // splunk: Splunk HTTP Event Collector format
)

// parsedConfig holds validated runtime configuration for HTTP source.
// Derived from pkgsource.InputConfig during initialization.
type parsedConfig struct {
	mode          string        // YAML: mode — push or pull. Default: push. Consumer: Run()
	scheme        string        // YAML: scheme from addr — http or https. Consumer: runPush (TLS setup)
	host          string        // YAML: host from addr/url — target hostname. Consumer: runPush/runPull
	port          string        // YAML: port from addr/url — target port. Consumer: runPush/runPull
	path          string        // YAML: path from addr/url — HTTP endpoint path. Consumer: runPush/runPull
	proto         protocol      // YAML: protocol — log format to parse. Consumer: buildAdapter
	token         string        // YAML: token — bearer/token auth for push endpoints. Consumer: buildPushHandler
	envelopeField string        // YAML: envelope_field — JSON field for envelope in ndjson. Consumer: GenericAdapter
	tlsCert       string        // YAML: tls_cert — TLS certificate path. Consumer: runPush (TLS server)
	tlsKey        string        // YAML: tls_key — TLS private key path. Consumer: runPush (TLS server)
	pullInterval  time.Duration // YAML: pull_interval — polling interval for pull mode. Default: 30s. Consumer: runPull
	maxBodyBytes  int64        // YAML: max_body_bytes — max request body size. Default: 10MB. Consumer: runPush
}

// parseHTTPConfig converts pkgsource.InputConfig to parsedConfig.
// Validates URL/addr format, sets defaults (mode=push, port=80/443), handles TLS.
// Returns error if required fields are missing or format is invalid.
// Called from: New() during HTTPSource initialization.
func parseHTTPConfig(cfg pkgsource.InputConfig) (*parsedConfig, error) {
	mode := cfg.Mode
	if mode == "" {
		mode = "push"
	}

	var u *url.URL
	var err error

	if mode == "push" {
		if cfg.Addr == "" {
			return nil, fmt.Errorf("http source: addr is required for push mode")
		}
		addr := cfg.Addr
		if !strings.Contains(addr, "://") {
			addr = "http://" + addr
		}
		u, err = url.Parse(addr)
		if err != nil {
			return nil, fmt.Errorf("http source: invalid addr %q: %w", cfg.Addr, err)
		}
	} else {
		if cfg.URL == "" {
			return nil, fmt.Errorf("http source: url is required for pull mode")
		}
		u, err = url.Parse(cfg.URL)
		if err != nil {
			return nil, fmt.Errorf("http source: invalid url %q: %w", cfg.URL, err)
		}
	}

	scheme := u.Scheme
	if scheme == "" {
		scheme = "http"
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	path := u.Path
	if path == "" {
		path = "/"
	}

	if scheme == "https" && (cfg.TLSCert == "" || cfg.TLSKey == "") {
		return nil, fmt.Errorf("http source: https requires tls_cert and tls_key")
	}

	proto, err := parseProtocol(cfg.Protocol)
	if err != nil {
		return nil, err
	}

	var pullInterval time.Duration
	if cfg.PullInterval != "" {
		pullInterval, err = time.ParseDuration(cfg.PullInterval)
		if err != nil {
			return nil, fmt.Errorf("http source: invalid pull_interval %q: %w", cfg.PullInterval, err)
		}
	} else {
		pullInterval = 30 * time.Second
	}

	maxBodyBytes := int64(cfg.MaxBodyBytes)
	if maxBodyBytes <= 0 {
		maxBodyBytes = 10 * 1024 * 1024
	}

	return &parsedConfig{
		mode:          mode,
		scheme:        scheme,
		host:          host,
		port:          port,
		path:          path,
		proto:         proto,
		token:         cfg.Token,
		envelopeField: cfg.EnvelopeField,
		tlsCert:       cfg.TLSCert,
		tlsKey:        cfg.TLSKey,
		pullInterval:  pullInterval,
		maxBodyBytes:  maxBodyBytes,
	}, nil
}

// parseProtocol converts protocol string to protocol enum.
// Returns error if protocol string is unknown or empty.
// Called from: parseHTTPConfig() during configuration parsing.
func parseProtocol(s string) (protocol, error) {
	switch s {
	case "plain":
		return protocolPlain, nil
	case "ndjson":
		return protocolNDJSON, nil
	case "cloudflare":
		return protocolCloudflare, nil
	case "firehose":
		return protocolFirehose, nil
	case "pubsub":
		return protocolPubSub, nil
	case "loki":
		return protocolLoki, nil
	case "otlp":
		return protocolOTLP, nil
	case "azure":
		return protocolAzure, nil
	case "splunk":
		return protocolSplunk, nil
	case "":
		return 0, fmt.Errorf("http source: protocol is required")
	default:
		return 0, fmt.Errorf("http source: unknown protocol %q", s)
	}
}