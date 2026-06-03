package http

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	pkgsource "github.com/mr-addams/arxsentinel/pkg/source"
)

type protocol int

const (
	protocolPlain      protocol = iota
	protocolNDJSON
	protocolCloudflare
	protocolFirehose
	protocolPubSub
	protocolLoki
	protocolOTLP
	protocolAzure
	protocolSplunk
)

type parsedConfig struct {
	mode          string
	scheme        string
	host          string
	port          string
	path          string
	proto         protocol
	token         string
	envelopeField string
	tlsCert       string
	tlsKey        string
	pullInterval  time.Duration
	maxBodyBytes  int64
}

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