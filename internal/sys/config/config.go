// ========================== Module config ==============================================
//
//	Single source of truth for all behavioral parameters of the project.
//	LoadConfig() — parses config.yaml with defaults, returns a populated Config.
//
//	WHAT IS HERE:
//	  - Config struct with nested sections per module
//	  - LoadConfig(path string) (Config, error) — the only public function
//	  - Duration — wrapper type for parsing strings like "300s", "24h" from YAML
//	  - defaultConfig() + defaultProbePaths() + defaultBots() — internal defaults
//
//	WHAT IS NOT HERE:
//	  - Business logic (core/)
//	  - Logging (sys/utils)
//
//	YAML PARSING:
//	  yaml.v3 overlays the YAML document on top of Go defaults field-by-field.
//	  Fields present in the file → set from YAML.
//	  Fields absent from the file (even inside a present section) → retain Go defaults.
//	  Sections absent from the file entirely → retain Go defaults unchanged.
//	  Verified empirically: partial sections are safe; omitted fields are never zeroed.
package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/mr-addams/arx-core/pkg/executor/queue"
	"github.com/mr-addams/arx-core/pkg/parser"
	"github.com/mr-addams/arxsentinel/internal/core/blocklist"
	"github.com/mr-addams/arxsentinel/internal/core/chaincheck"
)

// ========================== Duration helper type =======================================

// Duration — wrapper over time.Duration for correct parsing of strings from YAML.
// yaml.v3 cannot natively convert "300s", "24h" → time.Duration.
// Cast to time.Duration: time.Duration(cfg.Scoring.ObservationWindow).
type Duration time.Duration

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

// ========================== Root Config ===============================================

type Config struct {
	General    GeneralConfig    `yaml:"general"`
	Logging    LoggingConfig    `yaml:"logging"`
	Parser     ParserConfig     `yaml:"parser"`
	Scoring    ScoringConfig    `yaml:"scoring"`
	State      StateConfig      `yaml:"state"`
	Detectors  DetectorsConfig  `yaml:"detectors"`
	Whitelist  WhitelistConfig  `yaml:"whitelist"`
	Output     OutputConfig     `yaml:"output"`
	Metrics    MetricsConfig    `yaml:"metrics"`
	Blocklist  blocklist.Config `yaml:"blocklist"`   // YAML: blocklist — lists managed by blocklist.Manager (sources, refresh, bbolt). Consumer: main.go NewManager
	ChainGuard ChainGuardConfig `yaml:"chain_guard"` // YAML: chain_guard — proxy chain integrity checker. Consumer: main.go NewChecker
	Streams    []StreamConfig   `yaml:"streams"`     // YAML: streams — multi-stream mode; mutually exclusive with general.log_file

	// Universal I/O (Flow #030) — top-level for single-stream / no-streams mode.
	// Migrated from general.log_file + output.threat_log by Migrate().
	Inputs              []InputConfig         `yaml:"inputs"`                         // YAML: inputs — top-level source list; alternative to general.log_file
	Outputs             []SinkConfig          `yaml:"outputs"`                        // YAML: outputs — top-level sink list; alternative to output.threat_log
	DeprecatedExecutors []ExecutorItem        `yaml:"deprecated_executors,omitempty"` // YAML: deprecated_executors — legacy, replaced by top-level executors: (new format). Consumer: main.go, removed in v0.10.0
	Executors           []ExecutorTopConfig   `yaml:"executors"`                      // YAML: executors — top-level executor list with named channel switch sources. Consumer: main.go startExecutors
	Pipeline            PipelineRuntimeConfig `yaml:"pipeline"`                       // YAML: pipeline — buffer_size and shutdown_timeout; top-level default for all pipelines

	// Transport (Flow 093) — arx-core pkg/transport node-to-node mesh, gating
	// the "transport" queue.Queue backend used by Distributed NCS
	// (outputs[].queue.type: transport / inputs[].queue.type: transport).
	// Disabled by default (D21 invariant, inherited from arx-core): an
	// absent or Enabled:false transport: block means main.go never
	// constructs a *transport.Transport, and any queue.type: transport
	// entry elsewhere in this config fails validation (see
	// validateTransportWiring) rather than failing at runtime with a
	// confusing transportbridge.ErrNotConfigured three layers deep.
	Transport TransportConfig `yaml:"transport"` // YAML: transport — node-to-node mesh for Distributed NCS. Consumer: main.go bootstrap
}

// TransportConfig mirrors arx-core's transport.Config shape for YAML
// consumption — main.go translates this 1:1 into a transport.Config before
// calling transport.New (Flow 093 F1). Kept as a separate product-side type
// (not a direct YAML embed of transport.Config) because transport.Config's
// fields are plain Go, not yaml-tagged, and because the product owns its own
// config vocabulary independent of arx-core's internal struct shape.
type TransportConfig struct {
	Enabled        bool            `yaml:"enabled"`        // YAML: enabled — master gate (D21); false = no goroutine, no listener, no dial
	IdentityPath   string          `yaml:"identity"`       // YAML: identity — path to the node's Ed25519 private key file; generated on first start if absent. Required when enabled
	KnownNodesPath string          `yaml:"known_nodes"`    // YAML: known_nodes — path to the TOFU known-nodes file. Required when enabled. Fingerprint-keyed since arx-core v0.6.1 (Flow 006) — breaking format change, no migration
	Listen         string          `yaml:"listen"`         // YAML: listen — QUIC bind address, e.g. "0.0.0.0:4097". Required when enabled
	Peers          []TransportPeer `yaml:"peers"`          // YAML: peers — outbound dial targets (this node's roster)
	PairingSecret  string          `yaml:"pairing_secret"` // YAML: pairing_secret — mesh-wide admission secret (arx-core v0.6.1 Flow 006 Decision 2), identical on every node, exchanged out-of-band. Required when peers is non-empty. Gates FIRST CONTACT only — see arx-core's pkg/transport/OPERATIONS.md §1 "Pairing-Secret Provisioning"
}

// TransportPeer is one entry in TransportConfig.Peers — a node this
// process dials out to.
type TransportPeer struct {
	Host        string `yaml:"host"`        // YAML: host — peer's dial address, "host:port". Required.
	Fingerprint string `yaml:"fingerprint"` // YAML: fingerprint — pre-shared "sha256:<hex>"; empty = TOFU on first contact (D24 §5)
}

// ========================== Universal I/O config (Flow #030) ==========================

// InputConfig — configuration for a single log source.
// New syntax: inputs: [{type: file, path: /var/log/nginx/access.log, parser: combined}]
// Migration: general.log_file / streams[i].log_file → InputConfig automatically.
type InputConfig struct {
	Type           string `yaml:"type"`            // YAML: "file" | "stdin". Consumer: cmd/arxsentinel input.NewFileSource / input.NewStdinSource
	Path           string `yaml:"path"`            // YAML: path to log file; required when type=file. Consumer: input.NewFileSource
	Parser         string `yaml:"parser"`          // YAML: "combined" | "json" | "regex" | profile-name; default inherited from parser.log_format. Consumer: main.go buildParser
	Exec           string `yaml:"exec"`            // YAML: path to exec plugin binary; used when type="exec". Consumer: pkg/execplugin.NewSource
	Addr           string `yaml:"addr"`            // YAML: addr — network address for type=syslog: "udp://:5514", "tcp://:514", "unix:///var/run/arx.sock". Consumer: pkg/source/syslog.New
	Mode           string `yaml:"mode"`            // YAML: mode — "push" (listen) or "pull" (poll), default "push". Consumer: pkg/source/http.New
	URL            string `yaml:"url"`             // YAML: url — target URL for pull mode. Consumer: pkg/source/http.New
	HTTPPath       string `yaml:"http_path"`       // YAML: http_path — push handler path, default "/". Consumer: pkg/source/http.New
	Token          string `yaml:"token"`           // YAML: token — optional Bearer token for auth. Consumer: pkg/source/http.New
	TLSCert        string `yaml:"tls_cert"`        // YAML: tls_cert — path to TLS cert file; required for https://. Consumer: pkg/source/http.New
	TLSKey         string `yaml:"tls_key"`         // YAML: tls_key — path to TLS private key file; required for https://. Consumer: pkg/source/http.New
	Protocol       string `yaml:"protocol"`        // YAML: protocol — envelope format: plain|ndjson|cloudflare|firehose|pubsub|loki|otlp|azure|splunk. Consumer: pkg/source/http.New
	EnvelopeField  string `yaml:"envelope_field"`  // YAML: envelope_field — field name for ndjson extraction; required when protocol=ndjson. Consumer: pkg/source/http.New
	PullInterval   string `yaml:"pull_interval"`   // YAML: pull_interval — polling interval for pull mode, e.g. "30s". Consumer: pkg/source/http.New
	MaxBodyBytes   int    `yaml:"max_body_bytes"`  // YAML: max_body_bytes — max request body size, default 10485760. Consumer: pkg/source/http.New
	MaxConnections int    `yaml:"max_connections"` // YAML: max_connections — max concurrent TCP connections; syslog only, default 1000. Consumer: pkg/source/syslog.New (H5)

	// Queue (Flow 093) — explicit, opt-in queue backend for a "sentinel"
	// input's NCS name (parsed from Addr's "ncs://<name>" form). nil means
	// the existing behaviour: whatever queue is already registered under
	// that name (typically a plain in-process AttachWriter from a local
	// sentinel-threat sink — Distributed NCS is NOT implied just because
	// transport.enabled is true elsewhere in this config). Set
	// Queue.Type: transport, Queue.Mode: recv to make this input's queue
	// backed by arx-core's Distributed NCS mesh instead — see
	// preRegisterInboundTransportQueues (F3).
	Queue *queue.QueueConfig `yaml:"queue,omitempty"` // YAML: queue — optional backend for type=sentinel inputs; nil = existing AttachWriter/AttachReader behaviour unchanged
}

// SinkConfig — configuration for a single threat event output.
// New syntax: outputs: [{type: file, path: /var/log/arxsentinel/threats.log, format: fail2ban}]
// Migration: output.threat_log / streams[i].threat_log → SinkConfig automatically.
type SinkConfig struct {
	Type   string `yaml:"type"`   // YAML: "file" | "stdout". Consumer: cmd/arxsentinel output.NewFileSink / output.NewStdoutSink
	Name   string `yaml:"name"`   // YAML: named channel for sentinel-threat sink; used when type="sentinel-threat". Consumer: output.NewSentinelThreatSink
	Path   string `yaml:"path"`   // YAML: path to output file; required when type=file. Consumer: output.NewFileSink
	Format string `yaml:"format"` // YAML: "fail2ban" | "json" | "raw-line" (sentinel-threat only, Flow 093); default "fail2ban". Consumer: output.FileSink / output.StdoutSink / formatterForFormat
	Exec   string `yaml:"exec"`   // YAML: path to exec plugin binary; used when type="exec". Consumer: pkg/execplugin.NewSink

	// Queue (Flow 093) — explicit, opt-in queue backend for a
	// "sentinel-threat" sink's NCS name. nil means the existing
	// behaviour: NewSentinelThreatSink's own ncs.AttachWriter(name, 0)
	// (plain in-process memory queue, or a fan-in join if some other
	// registration — e.g. an executor source's Queue, or this same field
	// on another stream — already claimed the name first). Set
	// Queue.Type: transport, Queue.Mode: send (+ Queue.Peer) to forward
	// this sink's events to a remote node instead — see
	// preRegisterSinkQueues (F2), which registers Queue BEFORE the sink's
	// own AttachWriter call runs, so AttachWriter becomes a no-op fan-in
	// join onto the already-registered transport-backed queue.
	Queue *queue.QueueConfig `yaml:"queue,omitempty"` // YAML: queue — optional backend for type=sentinel-threat outputs; nil = existing AttachWriter behaviour unchanged

	// Loki-sink fields (Flow 097). Populated by host-side YAML for
	// type="loki" sinks. Used only by pkg/sink/loki; ignored by other
	// sinks. Mirror arx-core's pkgsink.SinkConfig 1:1 by name and type;
	// YAML keys are snake_case derivations of the Go field names.
	LokiURL           string            `yaml:"loki_url"`            // YAML: base URL of Loki push endpoint, e.g. "https://loki.example.com:3100". Required for type="loki".
	LokiLabels        map[string]string `yaml:"loki_labels"`         // YAML: static set of stream labels, e.g. {job: arxsentinel}. Required (non-empty) for type="loki" — Loki rejects streams without at least one label.
	LokiBatchSize     int               `yaml:"loki_batch_size"`     // YAML: max number of log lines per push request. No default here; pkg/sink/loki applies its own default if zero.
	LokiFlushInterval string            `yaml:"loki_flush_interval"` // YAML: max time between flushes (e.g. "5s"); parsed via time.ParseDuration in pkg/sink/loki/config.go. No default here; pkg/sink/loki applies its own default if empty.
	LokiTenantID      string            `yaml:"loki_tenant_id"`      // YAML: optional value for the X-Scope-OrgID header (multi-tenant Loki).
	LokiUsername      string            `yaml:"loki_username"`       // YAML: optional HTTP Basic Auth username (Grafana Cloud convention: instance ID). LokiPassword must also be set.
	LokiPassword      string            `yaml:"loki_password"`       // YAML: optional HTTP Basic Auth password (Grafana Cloud convention: API key). LokiUsername must also be set.
	LokiGzip          bool              `yaml:"loki_gzip"`           // YAML: optional; if true, request body is gzipped and Content-Encoding: gzip is set.
	LokiTLSCert       string            `yaml:"loki_tls_cert"`       // YAML: path to client TLS certificate (PEM). Optional; mTLS-style wiring.
	LokiTLSKey        string            `yaml:"loki_tls_key"`        // YAML: path to client TLS private key (PEM). Optional.
	LokiCACert        string            `yaml:"loki_ca_cert"`        // YAML: path to CA certificate (PEM) used to verify Loki. Optional.

	// Splunk-sink fields (Flow 097). Populated by host-side YAML for
	// type="splunk" sinks. Used only by pkg/sink/splunk; ignored by
	// other sinks. Mirror arx-core's pkgsink.SinkConfig 1:1 by name and
	// type; YAML keys are snake_case derivations of the Go field names.
	SplunkURL           string `yaml:"splunk_url"`            // YAML: base URL of the Splunk HEC endpoint, e.g. "https://splunk-host:8088". Required for type="splunk".
	SplunkToken         string `yaml:"splunk_token"`          // YAML: HEC token, sent as "Authorization: Splunk <token>". Required for type="splunk".
	SplunkSourceType    string `yaml:"splunk_source_type"`    // YAML: optional static sourcetype value applied to every event.
	SplunkSource        string `yaml:"splunk_source"`         // YAML: optional static source value applied to every event.
	SplunkIndex         string `yaml:"splunk_index"`          // YAML: optional static index name applied to every event.
	SplunkHost          string `yaml:"splunk_host"`           // YAML: optional static host value applied to every event.
	SplunkBatchSize     int    `yaml:"splunk_batch_size"`     // YAML: max number of events per push request. No default here; pkg/sink/splunk applies its own default if zero.
	SplunkFlushInterval string `yaml:"splunk_flush_interval"` // YAML: max time between flushes (e.g. "5s"); parsed via time.ParseDuration in pkg/sink/splunk/config.go. No default here.
	SplunkGzip          bool   `yaml:"splunk_gzip"`           // YAML: optional; if true, request body is gzipped and Content-Encoding: gzip is set. HEC's JSON-mode endpoint supports this.
	SplunkTLSCert       string `yaml:"splunk_tls_cert"`       // YAML: path to client TLS certificate (PEM). Optional; mTLS-style wiring.
	SplunkTLSKey        string `yaml:"splunk_tls_key"`        // YAML: path to client TLS private key (PEM). Optional.
	SplunkCACert        string `yaml:"splunk_ca_cert"`        // YAML: path to CA certificate (PEM) used to verify Splunk (HEC is commonly deployed with a self-signed cert). Optional.

	// Datadog-sink fields (Flow 097). Populated by host-side YAML for
	// type="datadog" sinks. Used only by pkg/sink/datadog; ignored by
	// other sinks. Mirror arx-core's pkgsink.SinkConfig 1:1 by name and
	// type; YAML keys are snake_case derivations of the Go field names.
	DatadogURL           string `yaml:"datadog_url"`            // YAML: full base URL of the Datadog Logs intake endpoint, including region, e.g. "https://http-intake.logs.datadoghq.com". Required for type="datadog".
	DatadogAPIKey        string `yaml:"datadog_api_key"`        // YAML: Datadog API key, sent as "DD-API-KEY: <key>" header. Required for type="datadog".
	DatadogSource        string `yaml:"datadog_source"`         // YAML: optional static ddsource value applied to every log.
	DatadogTags          string `yaml:"datadog_tags"`           // YAML: optional static ddtags value applied to every log; single comma-separated string (e.g. "env:prod,team:sre"), not a map — Datadog's own wire format.
	DatadogHostname      string `yaml:"datadog_hostname"`       // YAML: optional static hostname value applied to every log.
	DatadogService       string `yaml:"datadog_service"`        // YAML: optional static service value applied to every log.
	DatadogBatchSize     int    `yaml:"datadog_batch_size"`     // YAML: max number of logs per push request; must be <= 1000 (Datadog's hard limit — pkg/sink/datadog/config.go rejects values above it). No default here; pkg/sink/datadog applies its own default if zero.
	DatadogFlushInterval string `yaml:"datadog_flush_interval"` // YAML: max time between flushes (e.g. "5s"); parsed via time.ParseDuration in pkg/sink/datadog/config.go. No default here.
	DatadogGzip          bool   `yaml:"datadog_gzip"`           // YAML: optional; if true, request body is gzipped and Content-Encoding: gzip is set. Datadog recommends this for production; default is operator opt-in (false).
	DatadogTLSCert       string `yaml:"datadog_tls_cert"`       // YAML: path to client TLS certificate (PEM). Optional; mTLS-style wiring — uncommon for Datadog's public endpoints.
	DatadogTLSKey        string `yaml:"datadog_tls_key"`        // YAML: path to client TLS private key (PEM). Optional.
	DatadogCACert        string `yaml:"datadog_ca_cert"`        // YAML: path to CA certificate (PEM) used to verify Datadog. Optional — Datadog's public endpoints use publicly-trusted certs; this is for corporate TLS-inspecting proxies.
}

// ExecutorItem — configuration for a single executor instance (legacy).
// Deprecated in v0.10.0: use top-level executors with ExecutorTopConfig instead.
type ExecutorItem struct {
	Name   string                 `yaml:"name"`
	Type   string                 `yaml:"type"`
	Exec   string                 `yaml:"exec"`
	Params map[string]interface{} `yaml:"params,inline"`
	Config map[string]interface{} `yaml:"config"`
}

// ExecutorTopConfig — configuration for a single top-level executor instance.
// New syntax: executors: [{name: my-action, type: cloudflare, sources: [{name: cf-stream}], config: {…}}]
// Each executor reads ThreatEvents from Named Channel Switch sources listed in Sources.
type ExecutorTopConfig struct {
	Name    string                    `yaml:"name"`    // YAML: unique name for this executor instance
	Type    string                    `yaml:"type"`    // YAML: executor type registered in pkg/executor
	Sources []queue.ExecutorSourceRef `yaml:"sources"` // YAML: named channels to read ThreatEvents from
	Config  map[string]any            `yaml:"config"`  // YAML: executor-specific structured configuration
}

// PipelineRuntimeConfig — tuning parameters for the Source→Merge→Pipeline channel.
// Applied per-pipeline; top-level value is the default for pipelines without override.
type PipelineRuntimeConfig struct {
	BufferSize      int      `yaml:"buffer_size"`      // YAML: pipeline.buffer_size, default 8192 — bounded channel size between Merge and processor; increase for burst traffic. Consumer: input.Merge
	ShutdownTimeout Duration `yaml:"shutdown_timeout"` // YAML: pipeline.shutdown_timeout, default "15s" — max drain time on SIGTERM before forced close. Consumer: cmd/arxsentinel runPipeline
}

// DetectorConfig — per-pipeline configuration for a single detector.
// Enabled controls whether the detector runs in this pipeline.
// Params holds detector-specific parameters parsed by each detector's factory.
//
// Example YAML (inside a pipeline's detectors: map):
//
//	probe:
//	  enabled: true
//	  score: 10
//	  paths: [/.env, /.git/config]
type DetectorConfig struct {
	Enabled bool                   `yaml:"enabled"`
	Exec    string                 `yaml:"exec"`    // YAML: path to exec plugin binary; exec-based detector. Consumer: pkg/execplugin.NewDetector
	Params  map[string]interface{} `yaml:",inline"` // detector-specific params; deserialized by each factory
}

// ProcessorConfig holds the name and generic parameters for a processor plugin.
// Params is a string→any map — wire-up code type-asserts the values it needs.
// No import of pkg/processorplugins/* here: module boundary between config and plugins.
type ProcessorConfig struct {
	Plugin string         `yaml:"plugin"` // registered plugin name, e.g. "waf"
	Params map[string]any `yaml:"params"` // plugin-specific parameters
}

// PipelineConfig — one isolated processing unit within a stream.
// Each pipeline owns its Sources, Detectors, Sinks, and Tracker (or a shared Tracker group).
// Multiple pipelines within a stream run concurrently and are fully isolated by default.
//
// TrackerGroup: pipelines with the same non-empty group name share one *state.Tracker;
// an empty TrackerGroup means isolated (implicit group = pipeline Name).
type PipelineConfig struct {
	Name         string                    `yaml:"name"`          // YAML: pipelines[].name — label for metrics and logs; empty for auto-wrapped single pipeline
	TrackerGroup string                    `yaml:"tracker_group"` // YAML: pipelines[].tracker_group — shared IP-state group; "" → isolated
	Inputs       []InputConfig             `yaml:"inputs"`        // YAML: pipelines[].inputs — log sources for this pipeline
	Outputs      []SinkConfig              `yaml:"outputs"`       // YAML: pipelines[].outputs — threat sinks for this pipeline
	Detectors    map[string]DetectorConfig `yaml:"detectors"`     // YAML: pipelines[].detectors — per-detector config; nil → all registered with defaults
	Processors   []ProcessorConfig         `yaml:"processors"`    // YAML: pipelines[].processors — ordered list of processor plugins; nil → no processors. Consumer: processor_factory.Build
	Pipeline     PipelineRuntimeConfig     `yaml:"pipeline"`      // YAML: pipelines[].pipeline — buffer_size, shutdown_timeout

	// RawForward (Flow 093) — when true, this pipeline skips detection and
	// scoring entirely: every line is forwarded to Outputs as-is (the parsed
	// *parser.LogEntry, unscored). For Distributed NCS's raw-forward
	// scenario — a collector node with no local detection, forwarding every
	// line to a remote node's own detector chain (outputs[].queue.type:
	// transport + outputs[].format: raw-line). Without this flag, a
	// pipeline with detectors:{} produces NO events at all (the scorer
	// never crosses the alert threshold with zero detectors, so
	// securityProcessor.Process's normal level=="" early-return means
	// sink.Write is never called) — RawForward bypasses that gate on
	// purpose, it is not a side effect of an empty detector set.
	RawForward bool `yaml:"raw_forward"` // YAML: pipelines[].raw_forward — bypass detection/scoring, forward every line unscored. Consumer: cmd/arxsentinel securityProcessor.Process
}

// StreamConfig — a named logical group of pipelines sharing the same namespace for metrics and logs.
// Each stream has its own whitelist configuration; pipelines within a stream share whitelisting.
type StreamConfig struct {
	Name string `yaml:"name"` // YAML: streams[].name — label used in metrics and log output

	// Multi-pipeline syntax (Flow #034): each pipeline is an isolated processing unit.
	// If Pipelines is empty after YAML parsing, Migrate() auto-wraps Inputs/Outputs into Pipelines[0].
	Pipelines []PipelineConfig `yaml:"pipelines"` // YAML: streams[].pipelines — list of isolated pipelines

	// Single-pipeline I/O syntax (Flow #030): used when pipelines: is not specified.
	// Migrate() wraps these into Pipelines[0] before runStream() is called.
	Inputs     []InputConfig         `yaml:"inputs"`     // YAML: streams[].inputs — Deprecated in favour of pipelines[].inputs; auto-wrapped by Migrate()
	Outputs    []SinkConfig          `yaml:"outputs"`    // YAML: streams[].outputs — Deprecated in favour of pipelines[].outputs; auto-wrapped by Migrate()
	Executors  []ExecutorItem        `yaml:"executors"`  // YAML: streams[].executors — shorthand; Migrate() propagates to pipelines with Executors==nil. Consumer: config.Migrate
	Processors []ProcessorConfig     `yaml:"processors"` // YAML: streams[].processors — stream-level processor list; Migrate() propagates to pipelines with nil Processors. Consumer: config.Migrate
	Pipeline   PipelineRuntimeConfig `yaml:"pipeline"`   // YAML: streams[].pipeline — per-stream pipeline tuning; overrides top-level

	// Deprecated: use inputs/outputs instead. Kept for backward compatibility and
	// auto-migration via config.Migrate(). Will be removed in a future major version.
	LogFile   string `yaml:"log_file"`   // YAML: streams[].log_file — Deprecated: use inputs: [{type: file, path: ...}]
	ThreatLog string `yaml:"threat_log"` // YAML: streams[].threat_log — Deprecated: use outputs: [{type: file, path: ..., format: fail2ban}]
}

// ++++++++++++++++++++++++++ Section: general +++++++++++++++++++++++++++++++++++++++++++

type GeneralConfig struct {
	LogFile           string   `yaml:"log_file"`            // YAML: general.log_file, default "/var/log/nginx/access.log" — path to nginx access.log. Consumer: utils.TailReader
	PIDFile           string   `yaml:"pid_file"`            // YAML: general.pid_file, default "/var/run/arxsentinel.pid" — daemon PID file. Consumer: main.go
	LinesBufSize      int      `yaml:"lines_buf_size"`      // YAML: general.lines_buf_size, default 1000 — channel buffer between TailReader and line processor; increase for burst >1000 lines/sec. Consumer: main.go
	TailRetryInterval Duration `yaml:"tail_retry_interval"` // YAML: general.tail_retry_interval, default "5s" — retry interval when log_file is unavailable. Consumer: utils.TailReader
	StatsInterval     Duration `yaml:"stats_interval"`      // YAML: general.stats_interval, default "300s" — period for STATS output to operational.log. Consumer: main.go stats goroutine. Takes effect only on restart (goroutine starts once).
	// Daemon log file paths — in section output: (full paths, not a directory)
}

// ++++++++++++++++++++++++++ Section: logging ++++++++++++++++++++++++++++++++++++++++++++

type LoggingConfig struct {
	Debug        bool `yaml:"debug"`         // YAML: logging.debug, default false — show debugOnlyTags in console. Consumer: utils.DebugEnabled
	ConsoleColor bool `yaml:"console_color"` // YAML: logging.console_color, default true — color output in console. Consumer: utils.ColorEnabled
}

// ++++++++++++++++++++++++++ Section: parser +++++++++++++++++++++++++++++++++++++++++++++

type ParserConfig struct {
	Profile      string           `yaml:"profile"`       // YAML: parser.profile — built-in server profile: "apache" | "caddy" | "traefik" | "haproxy-http". Takes priority over log_format.
	LogFormat    string           `yaml:"log_format"`    // YAML: parser.log_format, default "combined" — "combined" | "json" | "regex". Consumer: main.go buildParser
	RegexPattern string           `yaml:"regex_pattern"` // YAML: parser.regex_pattern — Go regex with named groups; required when log_format = "regex"
	Timezone     string           `yaml:"timezone"`      // YAML: parser.timezone, default "UTC" — reserved; parser reads timezone from offset in log line (+0000). Consumer: not connected
	JSONFields   JSONFieldsConfig `yaml:"json_fields"`   // YAML: parser.json_fields — field name mapping for JSON log format. Consumer: JSONParser
}

// JSONFieldsConfig — alias to pkg/parser.JSONFieldsConfig.
// Decision 9 (DECISIONS.md, Flow 074): DTO relocated to pkg/parser so json.go can move
// to Core (pkg/) without internal/ dependencies. internal→pkg import is allowed by ADR-002.
// Composite literals (JSONFieldsConfig{...}) and field declarations remain valid —
// Go spec: alias types are interchangeable.
type JSONFieldsConfig = parser.JSONFieldsConfig

// ++++++++++++++++++++++++++ Section: scoring +++++++++++++++++++++++++++++++++++++++++++

type ScoringConfig struct {
	AlertThreshold    int      `yaml:"alert_threshold"`    // YAML: scoring.alert_threshold, default 50 — threshold for WARN level, written to threat log. Consumer: scorer.Evaluate
	BanThreshold      int      `yaml:"ban_threshold"`      // YAML: scoring.ban_threshold, default 80 — threshold for THREAT level, Fail2Ban bans IP. Consumer: scorer.Evaluate
	ObservationWindow Duration `yaml:"observation_window"` // YAML: scoring.observation_window, default "300s" — score accumulation window. Consumer: scorer.Decay, state.Tracker
	Decay             string   `yaml:"decay"`              // YAML: scoring.decay, default "linear" — decay algorithm ("linear"). Consumer: scorer.Decay
}

// ++++++++++++++++++++++++++ Section: state ++++++++++++++++++++++++++++++++++++++++++++++

type StateConfig struct {
	GCInterval    Duration `yaml:"gc_interval"`     // YAML: state.gc_interval, default "60s" — garbage collection run interval. Consumer: state.GC.Run
	MaxTrackedIPs int      `yaml:"max_tracked_ips"` // YAML: state.max_tracked_ips, default 100000 — in-memory IP limit (LRU eviction on overflow). Consumer: state.Tracker
}

// ++++++++++++++++++++++++++ Section: detectors ++++++++++++++++++++++++++++++++++++++++

type DetectorsConfig struct {
	Probe      ProbeConfig      `yaml:"probe"`
	Bruteforce BruteforceConfig `yaml:"bruteforce"`
	Crawler    CrawlerConfig    `yaml:"crawler"`
	NoAsset    NoAssetConfig    `yaml:"noasset"`
	Rate       RateConfig       `yaml:"rate"`
	UserAgent  UserAgentConfig  `yaml:"useragent"`
	Overflow   OverflowConfig   `yaml:"overflow"`
	BadBot     BadBotConfig     `yaml:"badbot"`
}

// -------------------------- Probe scanner --------------------------------------------

type ProbeConfig struct {
	Enabled bool     `yaml:"enabled"` // YAML: detectors.probe.enabled, default true — on/off switch. Consumer: detector.Probe
	Score   int      `yaml:"score"`   // YAML: detectors.probe.score, default 25 — points per probe request. Consumer: detector.Probe
	Paths   []string `yaml:"paths"`   // YAML: detectors.probe.paths — list of sensitive paths. Consumer: detector.Probe
}

// -------------------------- Path Bruteforce (404 ratio) ------------------------------

type BruteforceConfig struct {
	Enabled        bool    `yaml:"enabled"`         // YAML: detectors.bruteforce.enabled, default true. Consumer: detector.Bruteforce
	MinRequests    int     `yaml:"min_requests"`    // YAML: detectors.bruteforce.min_requests, default 10 — minimum requests before triggering. Consumer: detector.Bruteforce
	RatioThreshold float64 `yaml:"ratio_threshold"` // YAML: detectors.bruteforce.ratio_threshold, default 0.6 — 404 ratio threshold. Consumer: detector.Bruteforce
	Score          int     `yaml:"score"`           // YAML: detectors.bruteforce.score, default 30. Consumer: detector.Bruteforce
}

// -------------------------- Sequential Crawler ---------------------------------------

type CrawlerConfig struct {
	Enabled       bool `yaml:"enabled"`        // YAML: detectors.crawler.enabled, default true. Consumer: detector.Crawler
	MinSequential int  `yaml:"min_sequential"` // YAML: detectors.crawler.min_sequential, default 5 — minimum sequential URLs. Consumer: detector.Crawler
	Score         int  `yaml:"score"`          // YAML: detectors.crawler.score, default 20. Consumer: detector.Crawler
}

// -------------------------- No-Asset Bot --------------------------------------------

type NoAssetConfig struct {
	Enabled             bool     `yaml:"enabled"`               // YAML: detectors.noasset.enabled, default true. Consumer: detector.NoAsset
	MinPageRequests     int      `yaml:"min_page_requests"`     // YAML: detectors.noasset.min_page_requests, default 3. Consumer: detector.NoAsset
	AssetRatioThreshold float64  `yaml:"asset_ratio_threshold"` // YAML: detectors.noasset.asset_ratio_threshold, default 0.1 — less than 10% assets. Consumer: detector.NoAsset
	AssetExtensions     []string `yaml:"asset_extensions"`      // YAML: detectors.noasset.asset_extensions — static file extensions. Consumer: detector.NoAsset
	Score               int      `yaml:"score"`                 // YAML: detectors.noasset.score, default 20. Consumer: detector.NoAsset
}

// -------------------------- Rate Anomaly --------------------------------------------

type RateConfig struct {
	Enabled   bool     `yaml:"enabled"`   // YAML: detectors.rate.enabled, default true. Consumer: detector.Rate
	Window    Duration `yaml:"window"`    // YAML: detectors.rate.window, default "60s" — request counting window. Consumer: detector.Rate
	Threshold int      `yaml:"threshold"` // YAML: detectors.rate.threshold, default 100 — requests per window to trigger. Consumer: detector.Rate
	Score     int      `yaml:"score"`     // YAML: detectors.rate.score, default 25. Consumer: detector.Rate
}

// -------------------------- User-Agent Anomaly --------------------------------------

type UserAgentConfig struct {
	Enabled                 bool     `yaml:"enabled"`                   // YAML: detectors.useragent.enabled, default true. Consumer: detector.UserAgent
	ScannerScore            int      `yaml:"scanner_score"`             // YAML: detectors.useragent.scanner_score, default 40 — scanners (Nuclei, sqlmap). Consumer: detector.UserAgent
	GrabberScore            int      `yaml:"grabber_score"`             // YAML: detectors.useragent.grabber_score, default 20 — grabbers/crawlers. Consumer: detector.UserAgent
	AutomationScore         int      `yaml:"automation_score"`          // YAML: detectors.useragent.automation_score, default 15 — automation tools (requests, aiohttp). Consumer: detector.UserAgent
	EmptyUAScore            int      `yaml:"empty_ua_score"`            // YAML: detectors.useragent.empty_ua_score, default 30 — empty UA. Consumer: detector.UserAgent
	ExtraScannerPatterns    []string `yaml:"extra_scanner_patterns"`    // YAML: detectors.useragent.extra_scanner_patterns — additional scanner UA substrings merged with built-ins. Consumer: detector.UserAgent
	ExtraGrabberPatterns    []string `yaml:"extra_grabber_patterns"`    // YAML: detectors.useragent.extra_grabber_patterns — additional grabber UA substrings. Consumer: detector.UserAgent
	ExtraAutomationPatterns []string `yaml:"extra_automation_patterns"` // YAML: detectors.useragent.extra_automation_patterns — additional automation UA substrings. Consumer: detector.UserAgent
}

// -------------------------- Overflow / WAF Bypass -----------------------------------

type OverflowConfig struct {
	Enabled          bool     `yaml:"enabled"`           // YAML: detectors.overflow.enabled, default true. Consumer: detector.Overflow
	MaxURLLength     int      `yaml:"max_url_length"`    // YAML: detectors.overflow.max_url_length, default 2048 — URL length threshold. Consumer: detector.Overflow
	SuspiciousParams []string `yaml:"suspicious_params"` // YAML: detectors.overflow.suspicious_params — suspicious query parameters. Consumer: detector.Overflow
	Score            int      `yaml:"score"`             // YAML: detectors.overflow.score, default 30. Consumer: detector.Overflow
}

// -------------------------- Community Bad Bot Blocklist ------------------------------

// BadBotConfig controls the badbot detector.
// Sources, refresh intervals, and storage are now managed by blocklist.Manager
// via the top-level blocklist: config section. See D6 — Flow #025.
type BadBotConfig struct {
	Enabled       bool `yaml:"enabled"`        // YAML: detectors.badbot.enabled, default true. Consumer: detector.BadBot
	Score         int  `yaml:"score"`          // YAML: detectors.badbot.score, default 60 — points per match. Consumer: detector.BadBot
	CheckUA       bool `yaml:"check_ua"`       // YAML: detectors.badbot.check_ua, default true — match UA against "badbot-ua" list. Consumer: detector.BadBot
	CheckReferrer bool `yaml:"check_referrer"` // YAML: detectors.badbot.check_referrer, default false — match Referer against "badbot-ref" list. Consumer: detector.BadBot
}

// ++++++++++++++++++++++++++ Section: whitelist ++++++++++++++++++++++++++++++++++++++++

type WhitelistConfig struct {
	Bots             []BotConfig           `yaml:"bots"`
	Custom           CustomWhitelistConfig `yaml:"custom"`
	DNSCache         DNSCacheConfig        `yaml:"dns_cache"`
	FakeBotScore     int                   `yaml:"fake_bot_score"`     // YAML: whitelist.fake_bot_score, default 35 — penalty for a legitimate bot UA without DNS confirmation. Consumer: whitelist.Verifier
	DNSVerifyTimeout Duration              `yaml:"dns_verify_timeout"` // YAML: whitelist.dns_verify_timeout, default "2s" — bot DNS verification timeout in pipeline. Consumer: main.go processLine
}

// VerifyMethod constants — must match the yaml values in config.yaml.
const (
	VerifyMethodRDNS     = "rdns"
	VerifyMethodRDNSIP   = "rdns_ipjson"
	VerifyMethodIPRanges = "ip_ranges"
	VerifyMethodUAOnly   = "ua_only"
)

// BotConfig — a single legitimate bot with UA patterns and rDNS domains for verification.
type BotConfig struct {
	Name            string   `yaml:"name"`             // YAML: whitelist.bots[].name — identifier (google, bing...). Consumer: whitelist.Matcher
	UAPatterns      []string `yaml:"ua_patterns"`      // YAML: whitelist.bots[].ua_patterns — User-Agent substrings. Consumer: whitelist.Matcher
	RDNSDomains     []string `yaml:"rdns_domains"`     // YAML: whitelist.bots[].rdns_domains — allowed rDNS suffixes. Consumer: whitelist.Verifier
	VerifyMethod    string   `yaml:"verify_method"`    // YAML: whitelist.bots[].verify_method — "rdns" | "rdns_ipjson" | "ip_ranges" | "ua_only". Consumer: whitelist.Verifier
	ExemptDetectors []string `yaml:"exempt_detectors"` // YAML: whitelist.bots[].exempt_detectors — detector names to skip (e.g. ["noasset"]). Consumer: scorer.Evaluate, main.go processLine
}

type CustomWhitelistConfig struct {
	IPs          []string `yaml:"ips"`           // YAML: whitelist.custom.ips — trusted IPs. Consumer: whitelist.Matcher
	CIDRs        []string `yaml:"cidrs"`         // YAML: whitelist.custom.cidrs — trusted subnets. Consumer: whitelist.Matcher
	UASubstrings []string `yaml:"ua_substrings"` // YAML: whitelist.custom.ua_substrings — UA substrings to skip. Consumer: whitelist.Matcher
	Paths        []string `yaml:"paths"`         // YAML: whitelist.custom.paths — URL paths to skip scoring (e.g. ["/ws", "/health"]). Consumer: whitelist.Matcher
}

type DNSCacheConfig struct {
	PositiveTTL   Duration `yaml:"positive_ttl"`    // YAML: whitelist.dns_cache.positive_ttl, default "24h" — TTL for successful verification. Consumer: whitelist.IPCache
	NegativeTTL   Duration `yaml:"negative_ttl"`    // YAML: whitelist.dns_cache.negative_ttl, default "1h" — TTL for failed verification. Consumer: whitelist.IPCache
	IPListRefresh Duration `yaml:"ip_list_refresh"` // YAML: whitelist.dns_cache.ip_list_refresh, default "24h" — bot IP range refresh interval. Consumer: not connected (v0.2+, ip_ranges refresh)
}

// ++++++++++++++++++++++++++ Section: output ++++++++++++++++++++++++++++++++++++++++++++

type OutputConfig struct {
	ThreatLog      string `yaml:"threat_log"`      // YAML: output.threat_log, default "/var/log/arxsentinel/threats.log" — threat log for Fail2Ban. Consumer: output.Logger
	OperationalLog string `yaml:"operational_log"` // YAML: output.operational_log, default "/var/log/arxsentinel/sentinel.log" — daemon operational log. Consumer: utils.Init
}

// ++++++++++++++++++++++++++ Section: metrics ++++++++++++++++++++++++++++++++++++++++++++

// MetricsConfig holds Prometheus /metrics endpoint settings.
type MetricsConfig struct {
	Enabled      bool   `yaml:"enabled"`       // YAML: metrics.enabled, default false — enable Prometheus /metrics endpoint. Consumer: main.go metrics server
	ListenAddr   string `yaml:"listen_addr"`   // YAML: metrics.listen_addr, default ":9117" — address for the metrics HTTP server. Consumer: main.go metrics server. Port 9117 also appears in: Dockerfile EXPOSE, docker-compose.yml, .env.example, Docker README, K8s README — update all if default changes.
	Username     string `yaml:"username"`      // YAML: metrics.username — basic auth username; empty disables auth. Consumer: main.go metrics server
	PasswordHash string `yaml:"password_hash"` // YAML: metrics.password_hash — bcrypt hash of the password (cost ≥ 10). Consumer: main.go metrics server
}

// ++++++++++++++++++++++++++ Section: chain_guard +++++++++++++++++++++++++++++++++++++++

// ChainGuardConfig controls the chain integrity checker.
// When enabled, ArxSentinel detects Cloudflare or bogon IPs appearing as client IPs —
// a sign that the proxy chain is misconfigured and real attacker IPs are not reaching the log.
// Writes to WarningsLog (not threat_log) — these are infrastructure alerts, not threats.
type ChainGuardConfig struct {
	Enabled     bool                  `yaml:"enabled"`      // ENV: ARXSENTINEL_CHAIN_GUARD_ENABLED, default false (requires warnings_log to activate)
	WarningsLog string                `yaml:"warnings_log"` // ENV: ARXSENTINEL_CHAIN_GUARD_WARNINGS_LOG, default "" (required if enabled)
	Cloudflare  CloudflareGuardConfig `yaml:"cloudflare"`
	Bogon       BogonGuardConfig      `yaml:"bogon"`
}

// CloudflareGuardConfig controls Cloudflare IP range fetching and caching.
type CloudflareGuardConfig struct {
	Enabled         bool     `yaml:"enabled"`          // ENV: ARXSENTINEL_CHAIN_GUARD_CLOUDFLARE_ENABLED, default true
	RefreshInterval Duration `yaml:"refresh_interval"` // ENV: ARXSENTINEL_CHAIN_GUARD_CLOUDFLARE_REFRESH_INTERVAL, default 24h
	Sources         []string `yaml:"sources"`          // YAML only (slice) — default: cloudflare.com/ips-v4/ and ips-v6/
}

// BogonGuardConfig controls bogon/RFC1918/CGNAT IP detection.
// Uses a static built-in list — no network fetch required.
type BogonGuardConfig struct {
	Enabled bool `yaml:"enabled"` // ENV: ARXSENTINEL_CHAIN_GUARD_BOGON_ENABLED, default true
}

// ToChainCheckConfig converts ChainGuardConfig to the chaincheck package Config.
// Allows the config layer to remain decoupled from chaincheck internals —
// callers in main.go never import chaincheck directly for config construction.
func (c ChainGuardConfig) ToChainCheckConfig() chaincheck.Config {
	return chaincheck.Config{
		Cloudflare: chaincheck.CloudflareConfig{
			Enabled:         c.Cloudflare.Enabled,
			RefreshInterval: time.Duration(c.Cloudflare.RefreshInterval),
			Sources:         c.Cloudflare.Sources,
		},
		Bogon: chaincheck.BogonConfig{
			Enabled: c.Bogon.Enabled,
		},
	}
}

// ========================== Config loading ============================================

// LoadConfig reads config from path and overlays it on top of Go defaults.
//
// Load order (highest priority wins):
//  1. Go defaults (defaultConfig)
//  2. YAML file (if present)
//  3. ARXSENTINEL_* environment variables
//
// Behavior when file is missing:
//   - File not found (os.IsNotExist) → uses defaults; env overrides still apply.
//     The daemon works "out of the box" with sensible defaults.
//
// Behavior when file exists:
//   - Invalid YAML → returns error.
//   - Partial section (e.g. scoring: without ban_threshold) → unspecified fields
//     will be zeroed (yaml.v3 limitation). config.yaml must contain all fields of a section.
//
// Called from main.go at startup; repeated on SIGHUP (Task 7.1).
func LoadConfig(path string) (Config, error) {
	cfg := defaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return cfg, fmt.Errorf("reading config %q: %w", path, err)
		}
		// File not found — defaults are sufficient to start.
		// Print to stderr: the operator should know they are running on defaults.
		fmt.Fprintf(os.Stderr, "[INFO] config %q not found, using defaults\n", path)
	} else {
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return cfg, fmt.Errorf("parsing config %q: %w", path, err)
		}
	}

	// Env vars overlay YAML (or defaults when file is absent).
	// Return an empty Config on error — partial overrides are not a valid state.
	if err := applyEnvOverrides(&cfg); err != nil {
		return Config{}, err
	}

	// Normalize log_format to lowercase so buildParser() can compare without case sensitivity.
	cfg.Parser.LogFormat = strings.ToLower(cfg.Parser.LogFormat)

	// Backward compat: single general.log_file → synthesize a single unnamed stream.
	// Must happen BEFORE Migrate() so the synthesized stream is auto-wrapped into a pipeline.
	// Mutually exclusive with streams: — operator must not specify both.
	if cfg.General.LogFile != "" && len(cfg.Streams) > 0 {
		return cfg, fmt.Errorf("invalid config %q: general.log_file and streams: are mutually exclusive — use one or the other", path)
	}
	if len(cfg.Streams) == 0 {
		// Apply the log_file default only in single-stream mode so it does not
		// trigger the mutual-exclusion check when streams: is explicitly set.
		if cfg.General.LogFile == "" {
			cfg.General.LogFile = "/var/log/nginx/access.log"
		}
		cfg.Streams = []StreamConfig{{
			Name:      "",
			LogFile:   cfg.General.LogFile,
			ThreatLog: cfg.Output.ThreatLog,
		}}
	}

	// Universal I/O migration (Flow #030, #034): convert deprecated log_file/threat_log fields
	// to the new inputs/outputs syntax, then auto-wrap into pipelines.
	// Warnings are written to stderr so they appear in systemd journal before utils.Init() is called.
	if warnings := Migrate(&cfg); len(warnings) > 0 {
		for _, w := range warnings {
			fmt.Fprintf(os.Stderr, "[CONFIG] deprecation: %s\n", w)
		}
	}

	if err := validateConfig(&cfg); err != nil {
		return cfg, fmt.Errorf("invalid config %q: %w", path, err)
	}

	// Warning for high max_tracked_ips: each IP allocates an entry in the tracker
	// and a record in bbolt. >1,000,000 IPs can occupy >1GB RSS.
	if cfg.State.MaxTrackedIPs > 1_000_000 {
		fmt.Fprintf(os.Stderr, "[CONFIG] warning: state.max_tracked_ips=%d exceeds 1,000,000 — memory usage may exceed 1GB RSS\n", cfg.State.MaxTrackedIPs)
	}

	return cfg, nil
}

// ========================== Env var overrides =========================================

// applyEnvOverrides overlays ARXSENTINEL_* environment variables on top of cfg.
// Convention: ARXSENTINEL_<SECTION>_<FIELD> (uppercase, underscores).
// An empty or unset variable leaves the corresponding field unchanged.
//
// Not overridable via env vars (complex types — configure via YAML):
//
//	detectors.probe.paths, detectors.noasset.asset_extensions,
//	detectors.overflow.suspicious_params, detectors.useragent.extra_*_patterns,
//	whitelist.bots, whitelist.custom.ua_substrings, streams
func applyEnvOverrides(cfg *Config) error {
	// ── general ───────────────────────────────────────────────────────────────────────
	envStr("ARXSENTINEL_GENERAL_LOG_FILE", &cfg.General.LogFile)
	envStr("ARXSENTINEL_GENERAL_PID_FILE", &cfg.General.PIDFile)
	if err := envInt("ARXSENTINEL_GENERAL_LINES_BUF_SIZE", &cfg.General.LinesBufSize); err != nil {
		return err
	}
	if err := envDur("ARXSENTINEL_GENERAL_TAIL_RETRY_INTERVAL", &cfg.General.TailRetryInterval); err != nil {
		return err
	}
	if err := envDur("ARXSENTINEL_GENERAL_STATS_INTERVAL", &cfg.General.StatsInterval); err != nil {
		return err
	}

	// ── logging ───────────────────────────────────────────────────────────────────────
	if err := envBool("ARXSENTINEL_LOGGING_DEBUG", &cfg.Logging.Debug); err != nil {
		return err
	}
	if err := envBool("ARXSENTINEL_LOGGING_CONSOLE_COLOR", &cfg.Logging.ConsoleColor); err != nil {
		return err
	}

	// ── parser ────────────────────────────────────────────────────────────────────────
	envStr("ARXSENTINEL_PARSER_PROFILE", &cfg.Parser.Profile)
	envStr("ARXSENTINEL_PARSER_LOG_FORMAT", &cfg.Parser.LogFormat)
	envStr("ARXSENTINEL_PARSER_REGEX_PATTERN", &cfg.Parser.RegexPattern)
	envStr("ARXSENTINEL_PARSER_TIMEZONE", &cfg.Parser.Timezone)
	envStr("ARXSENTINEL_PARSER_JSON_REMOTE_ADDR", &cfg.Parser.JSONFields.RemoteAddr)
	envStr("ARXSENTINEL_PARSER_JSON_TIME", &cfg.Parser.JSONFields.Time)
	envStr("ARXSENTINEL_PARSER_JSON_REQUEST", &cfg.Parser.JSONFields.Request)
	envStr("ARXSENTINEL_PARSER_JSON_STATUS", &cfg.Parser.JSONFields.Status)
	envStr("ARXSENTINEL_PARSER_JSON_BYTES_SENT", &cfg.Parser.JSONFields.BytesSent)
	envStr("ARXSENTINEL_PARSER_JSON_REFERER", &cfg.Parser.JSONFields.Referer)
	envStr("ARXSENTINEL_PARSER_JSON_USER_AGENT", &cfg.Parser.JSONFields.UserAgent)
	envStr("ARXSENTINEL_PARSER_JSON_REAL_IP", &cfg.Parser.JSONFields.RealIP)

	// ── scoring ───────────────────────────────────────────────────────────────────────
	if err := envInt("ARXSENTINEL_SCORING_ALERT_THRESHOLD", &cfg.Scoring.AlertThreshold); err != nil {
		return err
	}
	if err := envInt("ARXSENTINEL_SCORING_BAN_THRESHOLD", &cfg.Scoring.BanThreshold); err != nil {
		return err
	}
	if err := envDur("ARXSENTINEL_SCORING_OBSERVATION_WINDOW", &cfg.Scoring.ObservationWindow); err != nil {
		return err
	}
	envStr("ARXSENTINEL_SCORING_DECAY", &cfg.Scoring.Decay)

	// ── state ─────────────────────────────────────────────────────────────────────────
	if err := envDur("ARXSENTINEL_STATE_GC_INTERVAL", &cfg.State.GCInterval); err != nil {
		return err
	}
	if err := envInt("ARXSENTINEL_STATE_MAX_TRACKED_IPS", &cfg.State.MaxTrackedIPs); err != nil {
		return err
	}

	// ── source ────────────────────────────────────────────────────────────────────────
	// ARXSENTINEL_SYSLOG_MAX_CONNECTIONS — global default for all syslog inputs.
	// Applied to every input with type=syslog that does not have max_connections set (==0).
	if v, ok := os.LookupEnv("ARXSENTINEL_SYSLOG_MAX_CONNECTIONS"); ok && v != "" {
		val, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("env ARXSENTINEL_SYSLOG_MAX_CONNECTIONS: invalid int %q", v)
		}
		if val <= 0 {
			return fmt.Errorf("env ARXSENTINEL_SYSLOG_MAX_CONNECTIONS must be > 0, got %d", val)
		}
		for i := range cfg.Inputs {
			if cfg.Inputs[i].Type == "syslog" && cfg.Inputs[i].MaxConnections <= 0 {
				cfg.Inputs[i].MaxConnections = val
			}
		}
	}

	// ── detectors.probe ───────────────────────────────────────────────────────────────
	if err := envBool("ARXSENTINEL_DETECTORS_PROBE_ENABLED", &cfg.Detectors.Probe.Enabled); err != nil {
		return err
	}
	if err := envInt("ARXSENTINEL_DETECTORS_PROBE_SCORE", &cfg.Detectors.Probe.Score); err != nil {
		return err
	}

	// ── detectors.bruteforce ──────────────────────────────────────────────────────────
	if err := envBool("ARXSENTINEL_DETECTORS_BRUTEFORCE_ENABLED", &cfg.Detectors.Bruteforce.Enabled); err != nil {
		return err
	}
	if err := envInt("ARXSENTINEL_DETECTORS_BRUTEFORCE_MIN_REQUESTS", &cfg.Detectors.Bruteforce.MinRequests); err != nil {
		return err
	}
	if err := envFloat("ARXSENTINEL_DETECTORS_BRUTEFORCE_RATIO_THRESHOLD", &cfg.Detectors.Bruteforce.RatioThreshold); err != nil {
		return err
	}
	if err := envInt("ARXSENTINEL_DETECTORS_BRUTEFORCE_SCORE", &cfg.Detectors.Bruteforce.Score); err != nil {
		return err
	}

	// ── detectors.crawler ─────────────────────────────────────────────────────────────
	if err := envBool("ARXSENTINEL_DETECTORS_CRAWLER_ENABLED", &cfg.Detectors.Crawler.Enabled); err != nil {
		return err
	}
	if err := envInt("ARXSENTINEL_DETECTORS_CRAWLER_MIN_SEQUENTIAL", &cfg.Detectors.Crawler.MinSequential); err != nil {
		return err
	}
	if err := envInt("ARXSENTINEL_DETECTORS_CRAWLER_SCORE", &cfg.Detectors.Crawler.Score); err != nil {
		return err
	}

	// ── detectors.noasset ─────────────────────────────────────────────────────────────
	if err := envBool("ARXSENTINEL_DETECTORS_NOASSET_ENABLED", &cfg.Detectors.NoAsset.Enabled); err != nil {
		return err
	}
	if err := envInt("ARXSENTINEL_DETECTORS_NOASSET_MIN_PAGE_REQUESTS", &cfg.Detectors.NoAsset.MinPageRequests); err != nil {
		return err
	}
	if err := envFloat("ARXSENTINEL_DETECTORS_NOASSET_ASSET_RATIO_THRESHOLD", &cfg.Detectors.NoAsset.AssetRatioThreshold); err != nil {
		return err
	}
	if err := envInt("ARXSENTINEL_DETECTORS_NOASSET_SCORE", &cfg.Detectors.NoAsset.Score); err != nil {
		return err
	}

	// ── detectors.rate ────────────────────────────────────────────────────────────────
	if err := envBool("ARXSENTINEL_DETECTORS_RATE_ENABLED", &cfg.Detectors.Rate.Enabled); err != nil {
		return err
	}
	if err := envDur("ARXSENTINEL_DETECTORS_RATE_WINDOW", &cfg.Detectors.Rate.Window); err != nil {
		return err
	}
	if err := envInt("ARXSENTINEL_DETECTORS_RATE_THRESHOLD", &cfg.Detectors.Rate.Threshold); err != nil {
		return err
	}
	if err := envInt("ARXSENTINEL_DETECTORS_RATE_SCORE", &cfg.Detectors.Rate.Score); err != nil {
		return err
	}

	// ── detectors.useragent ───────────────────────────────────────────────────────────
	if err := envBool("ARXSENTINEL_DETECTORS_USERAGENT_ENABLED", &cfg.Detectors.UserAgent.Enabled); err != nil {
		return err
	}
	if err := envInt("ARXSENTINEL_DETECTORS_USERAGENT_SCANNER_SCORE", &cfg.Detectors.UserAgent.ScannerScore); err != nil {
		return err
	}
	if err := envInt("ARXSENTINEL_DETECTORS_USERAGENT_GRABBER_SCORE", &cfg.Detectors.UserAgent.GrabberScore); err != nil {
		return err
	}
	if err := envInt("ARXSENTINEL_DETECTORS_USERAGENT_AUTOMATION_SCORE", &cfg.Detectors.UserAgent.AutomationScore); err != nil {
		return err
	}
	if err := envInt("ARXSENTINEL_DETECTORS_USERAGENT_EMPTY_UA_SCORE", &cfg.Detectors.UserAgent.EmptyUAScore); err != nil {
		return err
	}

	// ── detectors.overflow ────────────────────────────────────────────────────────────
	if err := envBool("ARXSENTINEL_DETECTORS_OVERFLOW_ENABLED", &cfg.Detectors.Overflow.Enabled); err != nil {
		return err
	}
	if err := envInt("ARXSENTINEL_DETECTORS_OVERFLOW_MAX_URL_LENGTH", &cfg.Detectors.Overflow.MaxURLLength); err != nil {
		return err
	}
	if err := envInt("ARXSENTINEL_DETECTORS_OVERFLOW_SCORE", &cfg.Detectors.Overflow.Score); err != nil {
		return err
	}

	// ── detectors.badbot ──────────────────────────────────────────────────────────────
	if err := envBool("ARXSENTINEL_DETECTORS_BADBOT_ENABLED", &cfg.Detectors.BadBot.Enabled); err != nil {
		return err
	}
	if err := envInt("ARXSENTINEL_DETECTORS_BADBOT_SCORE", &cfg.Detectors.BadBot.Score); err != nil {
		return err
	}
	if err := envBool("ARXSENTINEL_DETECTORS_BADBOT_CHECK_UA", &cfg.Detectors.BadBot.CheckUA); err != nil {
		return err
	}
	if err := envBool("ARXSENTINEL_DETECTORS_BADBOT_CHECK_REFERRER", &cfg.Detectors.BadBot.CheckReferrer); err != nil {
		return err
	}
	// ── chain_guard ───────────────────────────────────────────────────────────────────
	// Source URL lists are configured via YAML only (complex slices).
	// All scalar fields (enabled flags, path, refresh interval) support env overrides
	// so container deployments can toggle chain_guard behaviour without a YAML mount.
	if err := envBool("ARXSENTINEL_CHAIN_GUARD_ENABLED", &cfg.ChainGuard.Enabled); err != nil {
		return err
	}
	envStr("ARXSENTINEL_CHAIN_GUARD_WARNINGS_LOG", &cfg.ChainGuard.WarningsLog)
	if err := envBool("ARXSENTINEL_CHAIN_GUARD_CLOUDFLARE_ENABLED", &cfg.ChainGuard.Cloudflare.Enabled); err != nil {
		return err
	}
	if err := envDur("ARXSENTINEL_CHAIN_GUARD_CLOUDFLARE_REFRESH_INTERVAL", &cfg.ChainGuard.Cloudflare.RefreshInterval); err != nil {
		return err
	}
	if err := envBool("ARXSENTINEL_CHAIN_GUARD_BOGON_ENABLED", &cfg.ChainGuard.Bogon.Enabled); err != nil {
		return err
	}

	// ── blocklist ─────────────────────────────────────────────────────────────────────
	// Detailed source overrides (URLs, refresh intervals) are configured via YAML.
	// Only the storage path can be overridden via env for Docker/container deployments.
	envStr("ARXSENTINEL_BLOCKLIST_STORAGE", &cfg.Blocklist.Storage)

	// ── whitelist ─────────────────────────────────────────────────────────────────────
	if err := envInt("ARXSENTINEL_WHITELIST_FAKE_BOT_SCORE", &cfg.Whitelist.FakeBotScore); err != nil {
		return err
	}
	if err := envDur("ARXSENTINEL_WHITELIST_DNS_VERIFY_TIMEOUT", &cfg.Whitelist.DNSVerifyTimeout); err != nil {
		return err
	}
	if err := envDur("ARXSENTINEL_WHITELIST_DNS_CACHE_POSITIVE_TTL", &cfg.Whitelist.DNSCache.PositiveTTL); err != nil {
		return err
	}
	if err := envDur("ARXSENTINEL_WHITELIST_DNS_CACHE_NEGATIVE_TTL", &cfg.Whitelist.DNSCache.NegativeTTL); err != nil {
		return err
	}
	if err := envDur("ARXSENTINEL_WHITELIST_DNS_CACHE_IP_LIST_REFRESH", &cfg.Whitelist.DNSCache.IPListRefresh); err != nil {
		return err
	}
	// Comma-separated IP/CIDR lists — replaces (does not extend) the existing slice.
	// Validated at parse time so misconfigured addresses fail fast on startup.
	if err := envIPList("ARXSENTINEL_WHITELIST_CUSTOM_IPS", &cfg.Whitelist.Custom.IPs); err != nil {
		return err
	}
	if err := envCIDRList("ARXSENTINEL_WHITELIST_CUSTOM_CIDRS", &cfg.Whitelist.Custom.CIDRs); err != nil {
		return err
	}
	envCSV("ARXSENTINEL_WHITELIST_CUSTOM_PATHS", &cfg.Whitelist.Custom.Paths)

	// ── output ────────────────────────────────────────────────────────────────────────
	envStr("ARXSENTINEL_OUTPUT_THREAT_LOG", &cfg.Output.ThreatLog)
	envStr("ARXSENTINEL_OUTPUT_OPERATIONAL_LOG", &cfg.Output.OperationalLog)

	// ── metrics ───────────────────────────────────────────────────────────────────────
	if err := envBool("ARXSENTINEL_METRICS_ENABLED", &cfg.Metrics.Enabled); err != nil {
		return err
	}
	envStr("ARXSENTINEL_METRICS_LISTEN_ADDR", &cfg.Metrics.ListenAddr)
	envStr("ARXSENTINEL_METRICS_USERNAME", &cfg.Metrics.Username)
	envStr("ARXSENTINEL_METRICS_PASSWORD_HASH", &cfg.Metrics.PasswordHash)

	// ── pipeline ──────────────────────────────────────────────────────────────────────
	// Top-level pipeline tuning — allows container deployments to override buffer size
	// and shutdown timeout without modifying the YAML file.
	if err := envInt("ARXSENTINEL_PIPELINE_BUFFER_SIZE", &cfg.Pipeline.BufferSize); err != nil {
		return err
	}
	if err := envDur("ARXSENTINEL_PIPELINE_SHUTDOWN_TIMEOUT", &cfg.Pipeline.ShutdownTimeout); err != nil {
		return err
	}

	return nil
}

// ── env helpers ───────────────────────────────────────────────────────────────────────

// envStr sets *dst to the env value if the variable is set and non-empty.
func envStr(key string, dst *string) {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		*dst = v
	}
}

// envBool parses "true"/"false"/"1"/"0"; returns an error on unrecognized values.
func envBool(key string, dst *bool) error {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fmt.Errorf("env %s=%q: expected true/false/1/0", key, v)
	}
	*dst = b
	return nil
}

// envInt parses a base-10 integer; returns an error on invalid input.
func envInt(key string, dst *int) error {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fmt.Errorf("env %s=%q: expected integer", key, v)
	}
	*dst = n
	return nil
}

// envFloat parses a 64-bit float; returns an error on invalid input.
func envFloat(key string, dst *float64) error {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return nil
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return fmt.Errorf("env %s=%q: expected float", key, v)
	}
	*dst = f
	return nil
}

// envDur parses a Go duration string (e.g. "30s", "2m"); returns an error on invalid input.
func envDur(key string, dst *Duration) error {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fmt.Errorf("env %s=%q: expected duration (e.g. 30s, 2m)", key, v)
	}
	*dst = Duration(d)
	return nil
}

// envCSV splits a comma-separated env value into a string slice.
// Empty parts are dropped; the existing slice is replaced, not extended.
func envCSV(key string, dst *[]string) {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return
	}
	parts := strings.Split(v, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	*dst = result
}

// envIPList parses a comma-separated list of IP addresses.
// Each entry is validated with net.ParseIP; returns an error on invalid input.
func envIPList(key string, dst *[]string) error {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed == "" {
			continue
		}
		if net.ParseIP(trimmed) == nil {
			return fmt.Errorf("env %s: %q is not a valid IP address", key, trimmed)
		}
		result = append(result, trimmed)
	}
	*dst = result
	return nil
}

// envCIDRList parses a comma-separated list of CIDR blocks.
// Each entry is validated with net.ParseCIDR; returns an error on invalid input.
func envCIDRList(key string, dst *[]string) error {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(trimmed); err != nil {
			return fmt.Errorf("env %s: %q is not a valid CIDR block", key, trimmed)
		}
		result = append(result, trimmed)
	}
	*dst = result
	return nil
}

// isIPLike checks if s looks like an IP address (dotted decimal or IPv6).
// Used for sink name validation (C3) — IP-like names could bypass named channel routing.
func isIPLike(s string) bool {
	// Simple heuristic: ends with a digit, colon, or hex char after a dot.
	return net.ParseIP(s) != nil
}

// validateConfig checks critical fields after yaml.Unmarshal.
// Zero thresholds can occur if config.yaml specifies a scoring: section with
// incomplete fields (yaml.v3 partial merge limitation) — protects against silent misconfiguration.
func validateConfig(cfg *Config) error {
	// Top-level executors: unique names required.
	// Sink names must be static strings (not IP addresses — C3).
	// IP-like names would bypass named channel routing logic.
	for _, sink := range cfg.Outputs {
		if sink.Name != "" && isIPLike(sink.Name) {
			return fmt.Errorf("outputs: sink name %q looks like an IP address — use a descriptive name", sink.Name)
		}
	}

	if len(cfg.Executors) > 0 {
		seen := make(map[string]struct{}, len(cfg.Executors))
		for _, ex := range cfg.Executors {
			if _, dup := seen[ex.Name]; dup {
				return fmt.Errorf("executors: duplicate executor name %q", ex.Name)
			}
			seen[ex.Name] = struct{}{}
		}
	}
	if cfg.Scoring.AlertThreshold <= 0 {
		return fmt.Errorf("scoring.alert_threshold must be > 0, got %d", cfg.Scoring.AlertThreshold)
	}
	if cfg.Scoring.BanThreshold <= 0 {
		return fmt.Errorf("scoring.ban_threshold must be > 0, got %d", cfg.Scoring.BanThreshold)
	}
	if cfg.Scoring.BanThreshold <= cfg.Scoring.AlertThreshold {
		return fmt.Errorf("scoring.ban_threshold (%d) must be > alert_threshold (%d)",
			cfg.Scoring.BanThreshold, cfg.Scoring.AlertThreshold)
	}
	if time.Duration(cfg.Scoring.ObservationWindow) <= 0 {
		return fmt.Errorf("scoring.observation_window must be > 0")
	}
	if cfg.State.MaxTrackedIPs <= 0 {
		return fmt.Errorf("state.max_tracked_ips must be > 0, got %d", cfg.State.MaxTrackedIPs)
	}
	// Detector validation: zero thresholds cause panic or silent misconfiguration
	// with partial YAML (yaml.v3 partial merge zeroes unset fields in a section).
	// Detector score validation: every enabled detector must have score > 0.
	// Without this check a partial YAML section can silently zero the score,
	// causing the detector to trigger on every single request with accumulated score 0.
	if cfg.Detectors.Probe.Enabled && cfg.Detectors.Probe.Score <= 0 {
		return fmt.Errorf("detectors.probe.score must be > 0, got %d", cfg.Detectors.Probe.Score)
	}
	if cfg.Detectors.Bruteforce.Enabled {
		if cfg.Detectors.Bruteforce.MinRequests <= 0 {
			return fmt.Errorf("detectors.bruteforce.min_requests must be > 0, got %d",
				cfg.Detectors.Bruteforce.MinRequests)
		}
		if cfg.Detectors.Bruteforce.Score <= 0 {
			return fmt.Errorf("detectors.bruteforce.score must be > 0, got %d",
				cfg.Detectors.Bruteforce.Score)
		}
	}
	if cfg.Detectors.Crawler.Enabled {
		if cfg.Detectors.Crawler.MinSequential <= 0 {
			return fmt.Errorf("detectors.crawler.min_sequential must be > 0, got %d",
				cfg.Detectors.Crawler.MinSequential)
		}
		if cfg.Detectors.Crawler.Score <= 0 {
			return fmt.Errorf("detectors.crawler.score must be > 0, got %d",
				cfg.Detectors.Crawler.Score)
		}
	}
	if cfg.Detectors.NoAsset.Enabled {
		if cfg.Detectors.NoAsset.MinPageRequests <= 0 {
			return fmt.Errorf("detectors.noasset.min_page_requests must be > 0, got %d",
				cfg.Detectors.NoAsset.MinPageRequests)
		}
		if cfg.Detectors.NoAsset.Score <= 0 {
			return fmt.Errorf("detectors.noasset.score must be > 0, got %d",
				cfg.Detectors.NoAsset.Score)
		}
	}
	if cfg.Detectors.Rate.Enabled {
		if cfg.Detectors.Rate.Threshold <= 0 {
			return fmt.Errorf("detectors.rate.threshold must be > 0, got %d",
				cfg.Detectors.Rate.Threshold)
		}
		if time.Duration(cfg.Detectors.Rate.Window) <= 0 {
			return fmt.Errorf("detectors.rate.window must be > 0, got %v",
				cfg.Detectors.Rate.Window)
		}
		if cfg.Detectors.Rate.Score <= 0 {
			return fmt.Errorf("detectors.rate.score must be > 0, got %d",
				cfg.Detectors.Rate.Score)
		}
	}
	if cfg.Detectors.UserAgent.Enabled {
		if cfg.Detectors.UserAgent.ScannerScore <= 0 {
			return fmt.Errorf("detectors.useragent.scanner_score must be > 0, got %d",
				cfg.Detectors.UserAgent.ScannerScore)
		}
		if cfg.Detectors.UserAgent.GrabberScore <= 0 {
			return fmt.Errorf("detectors.useragent.grabber_score must be > 0, got %d",
				cfg.Detectors.UserAgent.GrabberScore)
		}
		if cfg.Detectors.UserAgent.AutomationScore <= 0 {
			return fmt.Errorf("detectors.useragent.automation_score must be > 0, got %d",
				cfg.Detectors.UserAgent.AutomationScore)
		}
		if cfg.Detectors.UserAgent.EmptyUAScore <= 0 {
			return fmt.Errorf("detectors.useragent.empty_ua_score must be > 0, got %d",
				cfg.Detectors.UserAgent.EmptyUAScore)
		}
	}
	if cfg.Detectors.Overflow.Enabled {
		if cfg.Detectors.Overflow.MaxURLLength <= 0 {
			return fmt.Errorf("detectors.overflow.max_url_length must be > 0, got %d",
				cfg.Detectors.Overflow.MaxURLLength)
		}
		if cfg.Detectors.Overflow.Score <= 0 {
			return fmt.Errorf("detectors.overflow.score must be > 0, got %d",
				cfg.Detectors.Overflow.Score)
		}
	}
	if cfg.Detectors.BadBot.Enabled {
		if cfg.Detectors.BadBot.Score <= 0 {
			return fmt.Errorf("detectors.badbot.score must be > 0, got %d", cfg.Detectors.BadBot.Score)
		}
	}
	// Blocklist lists validation: each configured list must have a name, refresh_interval > 0,
	// and at least one source with a non-empty URL.
	for i, l := range cfg.Blocklist.Lists {
		if l.Name == "" {
			return fmt.Errorf("blocklist.lists[%d].name must not be empty", i)
		}
		if time.Duration(l.RefreshInterval) <= 0 {
			return fmt.Errorf("blocklist.lists[%d] (%q): refresh_interval must be > 0", i, l.Name)
		}
		if len(l.Sources) == 0 {
			return fmt.Errorf("blocklist.lists[%d] (%q): must have at least one source", i, l.Name)
		}
		for j, src := range l.Sources {
			if src.URL == "" {
				return fmt.Errorf("blocklist.lists[%d] (%q) sources[%d]: url must not be empty", i, l.Name, j)
			}
		}
	}
	// chain_guard validation: warnings_log is required when chain_guard is enabled
	// because without a destination file there is nowhere to write infrastructure alerts.
	if cfg.ChainGuard.Enabled && cfg.ChainGuard.WarningsLog == "" {
		return fmt.Errorf("chain_guard.warnings_log must be set when chain_guard is enabled")
	}
	// Empty sources list is a misconfiguration — cloudflare checker would have no URLs to fetch
	// and would rely solely on the hardcoded fallback CIDRs without signalling the operator.
	if cfg.ChainGuard.Cloudflare.Enabled && len(cfg.ChainGuard.Cloudflare.Sources) == 0 {
		return fmt.Errorf("chain_guard.cloudflare.sources must not be empty when cloudflare check is enabled")
	}
	if cfg.Metrics.Username != "" && cfg.Metrics.PasswordHash == "" {
		return fmt.Errorf("metrics.password_hash must be set when metrics.username is configured")
	}
	// Pipeline validation (Flow #034): after Migrate(), every stream must have at least
	// one pipeline. Auto-wrap ensures this for legacy and single-pipeline configs.
	for i, s := range cfg.Streams {
		if len(s.Pipelines) == 0 {
			return fmt.Errorf("streams[%d]: must have at least one pipeline (Migrate() should have auto-wrapped inputs/outputs)", i)
		}
		// Check for duplicate pipeline names within a stream.
		pipelineNames := make(map[string]bool)
		for j, p := range s.Pipelines {
			if p.Name != "" {
				if pipelineNames[p.Name] {
					return fmt.Errorf("streams[%d]: duplicate pipeline name %q", i, p.Name)
				}
				pipelineNames[p.Name] = true
			}
			if len(p.Inputs) == 0 {
				return fmt.Errorf("streams[%d].pipelines[%d]: must have at least one input", i, j)
			}
			if len(p.Outputs) == 0 {
				// A pipeline without outputs silently drops all threat events — almost certainly a
				// misconfiguration. Require at least one sink for normal pipelines.
				return fmt.Errorf("streams[%d].pipelines[%d]: must have at least one output", i, j)
			}
			if err := validateInputs(p.Inputs); err != nil {
				return fmt.Errorf("streams[%d].pipelines[%d].inputs: %w", i, j, err)
			}
			if err := validateSinks(p.Outputs); err != nil {
				return fmt.Errorf("streams[%d].pipelines[%d].outputs: %w", i, j, err)
			}
		}
	}

	// Top-level I/O validation (Flow #030) — these are intermediate fields used by Migrate().
	if err := validateInputs(cfg.Inputs); err != nil {
		return err
	}
	if err := validateSinks(cfg.Outputs); err != nil {
		return err
	}
	if cfg.Pipeline.BufferSize < 0 {
		return fmt.Errorf("pipeline.buffer_size must be >= 0, got %d", cfg.Pipeline.BufferSize)
	}
	if cfg.Pipeline.ShutdownTimeout < 0 {
		return fmt.Errorf("pipeline.shutdown_timeout must be >= 0")
	}
	if err := validateTransportConfig(cfg.Transport); err != nil {
		return err
	}
	if err := validateTransportWiring(cfg); err != nil {
		return err
	}
	return nil
}

// validateTransportConfig checks TransportConfig's own required fields
// (Flow 093 E1). Enabled=false is always valid (D21: transport is fully
// optional) — the fields below are only required once the operator opts in.
func validateTransportConfig(t TransportConfig) error {
	if !t.Enabled {
		return nil
	}
	if t.IdentityPath == "" {
		return fmt.Errorf("transport.identity must be set when transport.enabled is true")
	}
	if t.KnownNodesPath == "" {
		return fmt.Errorf("transport.known_nodes must be set when transport.enabled is true")
	}
	if t.Listen == "" {
		return fmt.Errorf("transport.listen must be set when transport.enabled is true")
	}
	for i, p := range t.Peers {
		if p.Host == "" {
			return fmt.Errorf("transport.peers[%d].host must not be empty", i)
		}
	}
	if len(t.Peers) > 0 && t.PairingSecret == "" {
		return fmt.Errorf("transport.pairing_secret must be set when transport.peers is non-empty")
	}
	return nil
}

// validateTransportWiring checks that every queue.type: transport entry,
// wherever it appears (top-level / stream-level / pipeline-level outputs
// and inputs, plus executor sources), is only used when transport.enabled
// is true, and that its peer (when required — every mode except "recv")
// matches a host in transport.peers[] (Flow 093 E4). Catching a mismatch
// here means a misconfigured deployment fails at startup with a clear
// message instead of at the first Push/Pop call, deep inside
// pkg/ncs.RegisterSinkFromConfig or TransportQueue.
func validateTransportWiring(cfg *Config) error {
	knownPeers := make(map[string]bool, len(cfg.Transport.Peers))
	for _, p := range cfg.Transport.Peers {
		knownPeers[p.Host] = true
	}

	checkQueue := func(location string, q *queue.QueueConfig) error {
		if q == nil || q.Type != queue.QueueTypeTransport {
			return nil
		}
		if !cfg.Transport.Enabled {
			return fmt.Errorf("%s: queue.type=transport requires transport.enabled: true", location)
		}
		if q.EffectiveMode() != "recv" {
			if q.Peer == "" {
				return fmt.Errorf("%s: queue.peer is required for queue.type=transport (mode=%q)", location, q.EffectiveMode())
			}
			if !knownPeers[q.Peer] {
				return fmt.Errorf("%s: queue.peer %q does not match any transport.peers[].host", location, q.Peer)
			}
		}
		return nil
	}

	checkOutputs := func(prefix string, outs []SinkConfig) error {
		for i, o := range outs {
			if err := checkQueue(fmt.Sprintf("%s[%d]", prefix, i), o.Queue); err != nil {
				return err
			}
		}
		return nil
	}
	checkInputs := func(prefix string, ins []InputConfig) error {
		for i, in := range ins {
			if err := checkQueue(fmt.Sprintf("%s[%d]", prefix, i), in.Queue); err != nil {
				return err
			}
		}
		return nil
	}

	if err := checkOutputs("outputs", cfg.Outputs); err != nil {
		return err
	}
	if err := checkInputs("inputs", cfg.Inputs); err != nil {
		return err
	}
	for i, s := range cfg.Streams {
		if err := checkOutputs(fmt.Sprintf("streams[%d].outputs", i), s.Outputs); err != nil {
			return err
		}
		if err := checkInputs(fmt.Sprintf("streams[%d].inputs", i), s.Inputs); err != nil {
			return err
		}
		for j, p := range s.Pipelines {
			if err := checkOutputs(fmt.Sprintf("streams[%d].pipelines[%d].outputs", i, j), p.Outputs); err != nil {
				return err
			}
			if err := checkInputs(fmt.Sprintf("streams[%d].pipelines[%d].inputs", i, j), p.Inputs); err != nil {
				return err
			}
		}
	}
	for i, ex := range cfg.Executors {
		for j, src := range ex.Sources {
			if err := checkQueue(fmt.Sprintf("executors[%d].sources[%d]", i, j), src.Queue); err != nil {
				return err
			}
		}
	}
	return nil
}

// validateInputs checks a slice of InputConfig for structural errors.
func validateInputs(inputs []InputConfig) error {
	seen := make(map[string]bool)
	for i, in := range inputs {
		// Change (Flow 083): added "sentinel" — a legitimate top-level input,
		// registered in plugins_full (pkg/source/sentinel), reads from NCS.
		if in.Type != "file" && in.Type != "stdin" && in.Type != "exec" && in.Type != "syslog" && in.Type != "http" && in.Type != "sentinel" {
			return fmt.Errorf("inputs[%d]: unknown type %q (want file, stdin, exec, syslog, http, or sentinel)", i, in.Type)
		}
		if in.Type == "syslog" && in.Addr == "" {
			return fmt.Errorf("inputs[%d]: type=syslog requires addr (e.g. \"udp://:5514\")", i)
		}
		if in.Type == "http" {
			switch in.Mode {
			case "", "push":
				if in.Addr == "" {
					return fmt.Errorf("inputs[%d]: http push: addr is required", i)
				}
				if in.Protocol == "" {
					return fmt.Errorf("inputs[%d]: http push: protocol is required", i)
				}
				if strings.HasPrefix(in.Addr, "https://") {
					if in.TLSCert == "" {
						return fmt.Errorf("inputs[%d]: http https: tls_cert is required", i)
					}
					if in.TLSKey == "" {
						return fmt.Errorf("inputs[%d]: http https: tls_key is required", i)
					}
				}
			case "pull":
				if in.URL == "" {
					return fmt.Errorf("inputs[%d]: http pull: url is required", i)
				}
				if in.Protocol == "" {
					return fmt.Errorf("inputs[%d]: http pull: protocol is required", i)
				}
				if in.PullInterval == "" {
					return fmt.Errorf("inputs[%d]: http pull: pull_interval is required", i)
				}
				if strings.HasPrefix(in.URL, "https://") {
					if in.TLSCert == "" {
						return fmt.Errorf("inputs[%d]: http https: tls_cert is required", i)
					}
					if in.TLSKey == "" {
						return fmt.Errorf("inputs[%d]: http https: tls_key is required", i)
					}
				}
			default:
				return fmt.Errorf("inputs[%d]: http: unknown mode %q (want push or pull)", i, in.Mode)
			}
			if in.Protocol == "ndjson" && in.EnvelopeField == "" {
				return fmt.Errorf("inputs[%d]: http ndjson: envelope_field is required", i)
			}
		}
		// Duplicate detection key is type-specific: HTTP uses addr/url (no path), file/syslog use path.
		var key string
		switch in.Type {
		case "http":
			key = in.Type + ":" + in.Addr + ":" + in.URL
		default:
			key = in.Type + ":" + in.Path
		}
		if seen[key] {
			return fmt.Errorf("inputs[%d]: duplicate source %q", i, key)
		}
		seen[key] = true
		if in.Type == "file" && in.Path == "" {
			return fmt.Errorf("inputs[%d]: type=file requires path", i)
		}
	}
	return nil
}

// validateSinks checks a slice of SinkConfig for structural errors.
func validateSinks(sinks []SinkConfig) error {
	seen := make(map[string]bool)
	for i, s := range sinks {
		key := s.Type + ":" + s.Path
		if seen[key] {
			return fmt.Errorf("outputs[%d]: duplicate sink %q", i, key)
		}
		seen[key] = true
		if s.Type == "file" && s.Path == "" {
			return fmt.Errorf("outputs[%d]: type=file requires path", i)
		}
		if s.Format != "" && s.Format != "fail2ban" && s.Format != "json" && s.Format != "sentinel-threat" && s.Format != "raw-line" {
			return fmt.Errorf("outputs[%d]: unknown format %q (want fail2ban, json, sentinel-threat, or raw-line)", i, s.Format)
		}
		// raw-line (Flow 093) is meaningful only on a sentinel-threat sink —
		// it is a pre-detection wire format for Distributed NCS's raw-forward
		// scenario, not a general-purpose file/stdout format.
		if s.Format == "raw-line" && s.Type != "sentinel-threat" {
			return fmt.Errorf("outputs[%d]: format=raw-line is only valid for type=sentinel-threat", i)
		}
	}
	return nil
}

// ========================== Defaults ==================================================

// defaultConfig returns a Config with all defaults.
// Serves as the base: yaml.Unmarshal overlays only the sections present in the file.
// Sections absent from the file (e.g. no `state:`) retain the values from this function.
func defaultConfig() Config {
	return Config{
		General: GeneralConfig{
			// LogFile default is applied lazily in the backward-compat block below
			// so it does not conflict with streams: when streams: is explicitly set.
			PIDFile:           "/run/arxsentinel/arxsentinel.pid",
			LinesBufSize:      1000,
			TailRetryInterval: Duration(5 * time.Second),
			StatsInterval:     Duration(300 * time.Second),
		},
		Logging: LoggingConfig{
			Debug:        false,
			ConsoleColor: true,
		},
		Parser: ParserConfig{
			LogFormat: "combined",
			Timezone:  "UTC",
			JSONFields: JSONFieldsConfig{
				RemoteAddr: "remote_addr",
				Time:       "time_iso8601",
				Request:    "request",
				Status:     "status",
				BytesSent:  "bytes_sent",
				Referer:    "http_referer",
				UserAgent:  "http_user_agent",
				RealIP:     "real_ip",
			},
		},
		Scoring: ScoringConfig{
			AlertThreshold:    50,
			BanThreshold:      80,
			ObservationWindow: Duration(300 * time.Second),
			Decay:             "linear",
		},
		State: StateConfig{
			GCInterval:    Duration(60 * time.Second),
			MaxTrackedIPs: 100000,
		},
		Detectors: DetectorsConfig{
			Probe: ProbeConfig{
				Enabled: true,
				Score:   25,
				Paths:   defaultProbePaths(),
			},
			Bruteforce: BruteforceConfig{
				Enabled:        true,
				MinRequests:    10,
				RatioThreshold: 0.6,
				Score:          30,
			},
			Crawler: CrawlerConfig{
				Enabled:       true,
				MinSequential: 5,
				Score:         20,
			},
			NoAsset: NoAssetConfig{
				Enabled:             true,
				MinPageRequests:     3,
				AssetRatioThreshold: 0.1,
				AssetExtensions:     []string{".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2", ".ttf", ".ico", ".webp"},
				Score:               20,
			},
			Rate: RateConfig{
				Enabled:   true,
				Window:    Duration(60 * time.Second),
				Threshold: 100,
				Score:     25,
			},
			UserAgent: UserAgentConfig{
				Enabled:         true,
				ScannerScore:    40,
				GrabberScore:    20,
				AutomationScore: 15,
				EmptyUAScore:    30,
			},
			Overflow: OverflowConfig{
				Enabled:          true,
				MaxURLLength:     2048,
				SuspiciousParams: []string{"bypass", "shell", "cmd", "exec", "eval", "system", "passthru"},
				Score:            30,
			},
			BadBot: BadBotConfig{
				Enabled:       true,
				Score:         60,
				CheckUA:       true,
				CheckReferrer: false,
			},
		},
		Whitelist: WhitelistConfig{
			Bots:             defaultBots(),
			Custom:           CustomWhitelistConfig{},
			FakeBotScore:     35,
			DNSVerifyTimeout: Duration(2 * time.Second),
			DNSCache: DNSCacheConfig{
				PositiveTTL:   Duration(24 * time.Hour),
				NegativeTTL:   Duration(time.Hour),
				IPListRefresh: Duration(24 * time.Hour),
			},
		},
		Output: OutputConfig{
			ThreatLog:      "/var/log/arxsentinel/threats.log",
			OperationalLog: "/var/log/arxsentinel/sentinel.log",
		},
		Pipeline: PipelineRuntimeConfig{
			BufferSize:      8192,
			ShutdownTimeout: Duration(15 * time.Second),
		},
		Metrics: MetricsConfig{
			Enabled:    false,
			ListenAddr: ":9117",
		},
		// ChainGuard default: disabled so the daemon starts without configuration.
		// Operator must set enabled: true and provide warnings_log to activate.
		// WarningsLog is required when enabled — validation enforces this at startup.
		ChainGuard: ChainGuardConfig{
			Enabled:     false,
			WarningsLog: "",
			Cloudflare: CloudflareGuardConfig{
				Enabled:         true,
				RefreshInterval: Duration(24 * time.Hour),
				Sources: []string{
					"https://www.cloudflare.com/ips-v4/",
					"https://www.cloudflare.com/ips-v6/",
				},
			},
			Bogon: BogonGuardConfig{
				Enabled: true,
			},
		},
		// Blocklist defaults provide the mitchellkrogza community lists out of the box.
		// Blocklist sources (URLs, format) live exclusively in config.yaml — not here.
		// Go defaults only declare that both lists are enabled; the yaml provides the URLs.
		// This avoids URL duplication across config.yaml, config.docker.yaml, and code.
		Blocklist: blocklist.Config{
			Storage: "",
			Lists:   []blocklist.ListConfig{},
		},
	}
}

// defaultProbePaths — list of sensitive paths for the probe detector.
// Covers: app configs, VCS, cloud credentials, CMS, backups, infrastructure, debug.
// Extracted to avoid cluttering defaultConfig().
func defaultProbePaths() []string {
	return []string{
		// Application configuration files
		"/.env", "/.env.backup", "/.env.local", "/.env.production", "/.env.staging",
		"/config.yml", "/config.yaml", "/config.json", "/application.properties",
		"/settings.py", "/local_settings.py", "/database.yml", "/database.yaml",
		"/web.config", "/app.config",

		// Git / VCS
		"/.git/config", "/.git/HEAD", "/.gitignore",
		"/.svn/entries", "/.hg/", "/.bzr/",

		// Cloud credentials
		"/.aws/credentials", "/.docker/config.json",
		"/aws-exports.json", "/.gcloud/credentials",

		// CMS: WordPress
		"/wp-config.php", "/wp-config.php.bak", "/wp-config.php.old",
		"/wp-login.php", "/xmlrpc.php", "/wp-admin/",

		// CMS: general
		"/administrator/", "/admin/", "/phpmyadmin/", "/pma/",
		"/joomla/", "/drupal/", "/typo3/",

		// Backup files
		"/backup.zip", "/backup.tar.gz", "/backup.sql", "/backup.sql.gz",
		"/db.dump", "/database.sql", "/dump.sql", "/site.sql",

		// Infrastructure and monitoring
		"/server-status", "/server-info",
		"/phpinfo.php", "/info.php", "/php.php",
		"/actuator/", "/actuator/env", "/actuator/health", "/actuator/mappings",
		"/metrics", "/health", "/.well-known/",

		// Debug / API endpoints
		"/.debug", "/trace", "/console",
		"/graphql", "/graphiql", "/api/graphql",
	}
}

// defaultBots — list of legitimate search bots from spec section 4.2.
// Each bot is verified by UA pattern + rDNS + (optionally) fDNS or IP ranges.
func defaultBots() []BotConfig {
	return []BotConfig{
		{
			Name:         "google",
			UAPatterns:   []string{"Googlebot", "Google-InspectionTool", "GoogleOther", "AdsBot-Google"},
			RDNSDomains:  []string{".googlebot.com", ".google.com"},
			VerifyMethod: "rdns_ipjson",
		},
		{
			Name:         "bing",
			UAPatterns:   []string{"bingbot", "BingPreview", "msnbot", "adidxbot"},
			RDNSDomains:  []string{".search.msn.com"},
			VerifyMethod: "rdns",
		},
		{
			Name:         "yandex",
			UAPatterns:   []string{"YandexBot", "YandexImages", "YandexMetrika", "YandexDirect"},
			RDNSDomains:  []string{".yandex.ru", ".yandex.net", ".yandex.com"},
			VerifyMethod: "rdns",
		},
		{
			Name:         "duckduckgo",
			UAPatterns:   []string{"DuckDuckBot"},
			RDNSDomains:  []string{".duckduckgo.com"},
			VerifyMethod: "rdns",
		},
		{
			Name:         "baidu",
			UAPatterns:   []string{"Baiduspider", "BaiduMobaider"},
			RDNSDomains:  []string{".baidu.com", ".baidu.jp"},
			VerifyMethod: "rdns",
		},
		{
			Name:         "apple",
			UAPatterns:   []string{"Applebot"},
			RDNSDomains:  []string{".applebot.apple.com"},
			VerifyMethod: "rdns",
		},
		{
			Name:         "facebook",
			UAPatterns:   []string{"facebookexternalhit", "Facebot"},
			RDNSDomains:  []string{},
			VerifyMethod: "ip_ranges",
		},
		{
			Name:         "twitter",
			UAPatterns:   []string{"Twitterbot"},
			RDNSDomains:  []string{},
			VerifyMethod: "ip_ranges",
		},
		{
			Name:         "telegram",
			UAPatterns:   []string{"TelegramBot"},
			RDNSDomains:  []string{},
			VerifyMethod: "ip_ranges",
		},
		{
			Name:            "claudebot",
			UAPatterns:      []string{"ClaudeBot", "Claude-Web", "anthropic-ai"},
			RDNSDomains:     []string{},
			VerifyMethod:    VerifyMethodUAOnly,
			ExemptDetectors: []string{"noasset"},
		},
		{
			Name:            "gptbot",
			UAPatterns:      []string{"GPTBot", "OAI-SearchBot", "ChatGPT-User"},
			RDNSDomains:     []string{},
			VerifyMethod:    VerifyMethodUAOnly,
			ExemptDetectors: []string{"noasset"},
		},
		{
			Name:            "amazonbot",
			UAPatterns:      []string{"Amazonbot"},
			RDNSDomains:     []string{},
			VerifyMethod:    VerifyMethodUAOnly,
			ExemptDetectors: []string{"noasset"},
		},
		{
			Name:            "meta-crawler",
			UAPatterns:      []string{"meta-externalagent", "meta-externalfetcher"},
			RDNSDomains:     []string{},
			VerifyMethod:    VerifyMethodUAOnly,
			ExemptDetectors: []string{"noasset"},
		},
	}
}
