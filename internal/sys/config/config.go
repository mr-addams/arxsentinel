// ========================== Module config ==============================================
//   Single source of truth for all behavioral parameters of the project.
//   LoadConfig() — parses config.yaml with defaults, returns a populated Config.
//
//   WHAT IS HERE:
//     - Config struct with nested sections per module
//     - LoadConfig(path string) (Config, error) — the only public function
//     - Duration — wrapper type for parsing strings like "300s", "24h" from YAML
//     - defaultConfig() + defaultProbePaths() + defaultBots() — internal defaults
//
//   WHAT IS NOT HERE:
//     - Business logic (core/)
//     - Logging (sys/utils)
//
//   YAML PARSING LIMITATION:
//     yaml.v3 overlays values on top of defaults at the section level as a whole.
//     If config.yaml specifies a scoring: section, it must contain ALL fields —
//     otherwise unspecified fields will be zeroed (yaml.v3 does not support partial merge).
//     Sections absent from the file entirely retain their Go defaults.

package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

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
	General   GeneralConfig   `yaml:"general"`
	Logging   LoggingConfig   `yaml:"logging"`
	Parser    ParserConfig    `yaml:"parser"`
	Scoring   ScoringConfig   `yaml:"scoring"`
	State     StateConfig     `yaml:"state"`
	Detectors DetectorsConfig `yaml:"detectors"`
	Whitelist WhitelistConfig `yaml:"whitelist"`
	Output    OutputConfig    `yaml:"output"`
	Metrics   MetricsConfig   `yaml:"metrics"`
	Blocklist  blocklist.Config  `yaml:"blocklist"`   // YAML: blocklist — lists managed by blocklist.Manager (sources, refresh, bbolt). Consumer: main.go NewManager
	ChainGuard ChainGuardConfig  `yaml:"chain_guard"` // YAML: chain_guard — proxy chain integrity checker. Consumer: main.go NewChecker
	Streams    []StreamConfig    `yaml:"streams"`     // YAML: streams — multi-stream mode; mutually exclusive with general.log_file
}

// StreamConfig defines one log-watching pipeline.
// Each stream has its own tracker, scorer, whitelist, and threat log — full isolation.
type StreamConfig struct {
	Name      string `yaml:"name"`       // YAML: streams[].name — label used in metrics and log output
	LogFile   string `yaml:"log_file"`   // YAML: streams[].log_file — path to the access log to watch
	ThreatLog string `yaml:"threat_log"` // YAML: streams[].threat_log — path to the per-stream threat log (Fail2Ban reads this)
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

// JSONFieldsConfig maps LogEntry fields to the actual JSON key names in the nginx log.
// Allows users to customize nginx log_format json without changing sentinel config structure.
// All fields default to standard nginx variable names.
type JSONFieldsConfig struct {
	RemoteAddr string `yaml:"remote_addr"`  // default "remote_addr"
	Time       string `yaml:"time"`         // default "time_iso8601"
	Request    string `yaml:"request"`      // default "request" — "METHOD /uri PROTO" string
	Status     string `yaml:"status"`       // default "status"
	BytesSent  string `yaml:"bytes_sent"`   // default "bytes_sent"
	Referer    string `yaml:"referer"`      // default "http_referer"
	UserAgent  string `yaml:"user_agent"`   // default "http_user_agent"
	RealIP     string `yaml:"real_ip"`      // default "real_ip"
}

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
	Enabled                bool     `yaml:"enabled"`                  // YAML: detectors.useragent.enabled, default true. Consumer: detector.UserAgent
	ScannerScore           int      `yaml:"scanner_score"`            // YAML: detectors.useragent.scanner_score, default 40 — scanners (Nuclei, sqlmap). Consumer: detector.UserAgent
	GrabberScore           int      `yaml:"grabber_score"`            // YAML: detectors.useragent.grabber_score, default 20 — grabbers/crawlers. Consumer: detector.UserAgent
	AutomationScore        int      `yaml:"automation_score"`         // YAML: detectors.useragent.automation_score, default 15 — automation tools (requests, aiohttp). Consumer: detector.UserAgent
	EmptyUAScore           int      `yaml:"empty_ua_score"`           // YAML: detectors.useragent.empty_ua_score, default 30 — empty UA. Consumer: detector.UserAgent
	ExtraScannerPatterns   []string `yaml:"extra_scanner_patterns"`   // YAML: detectors.useragent.extra_scanner_patterns — additional scanner UA substrings merged with built-ins. Consumer: detector.UserAgent
	ExtraGrabberPatterns   []string `yaml:"extra_grabber_patterns"`   // YAML: detectors.useragent.extra_grabber_patterns — additional grabber UA substrings. Consumer: detector.UserAgent
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
	Bots             []BotConfig          `yaml:"bots"`
	Custom           CustomWhitelistConfig `yaml:"custom"`
	DNSCache         DNSCacheConfig        `yaml:"dns_cache"`
	FakeBotScore     int                  `yaml:"fake_bot_score"`      // YAML: whitelist.fake_bot_score, default 35 — penalty for a legitimate bot UA without DNS confirmation. Consumer: whitelist.Verifier
	DNSVerifyTimeout Duration             `yaml:"dns_verify_timeout"`  // YAML: whitelist.dns_verify_timeout, default "2s" — bot DNS verification timeout in pipeline. Consumer: main.go processLine
}

// BotConfig — a single legitimate bot with UA patterns and rDNS domains for verification.
type BotConfig struct {
	Name         string   `yaml:"name"`          // YAML: whitelist.bots[].name — identifier (google, bing...). Consumer: whitelist.Matcher
	UAPatterns   []string `yaml:"ua_patterns"`   // YAML: whitelist.bots[].ua_patterns — User-Agent substrings. Consumer: whitelist.Matcher
	RDNSDomains  []string `yaml:"rdns_domains"`  // YAML: whitelist.bots[].rdns_domains — allowed rDNS suffixes. Consumer: whitelist.Verifier
	VerifyMethod string   `yaml:"verify_method"` // YAML: whitelist.bots[].verify_method — "rdns" | "rdns_ipjson" | "ip_ranges". Consumer: whitelist.Verifier
}

type CustomWhitelistConfig struct {
	IPs          []string `yaml:"ips"`           // YAML: whitelist.custom.ips — trusted IPs. Consumer: whitelist.Matcher
	CIDRs        []string `yaml:"cidrs"`         // YAML: whitelist.custom.cidrs — trusted subnets. Consumer: whitelist.Matcher
	UASubstrings []string `yaml:"ua_substrings"` // YAML: whitelist.custom.ua_substrings — UA substrings to skip. Consumer: whitelist.Matcher
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
	ListenAddr   string `yaml:"listen_addr"`   // YAML: metrics.listen_addr, default ":9117" — address for the metrics HTTP server. Consumer: main.go metrics server
	Username     string `yaml:"username"`      // YAML: metrics.username — basic auth username; empty disables auth. Consumer: main.go metrics server
	PasswordHash string `yaml:"password_hash"` // YAML: metrics.password_hash — bcrypt hash of the password (cost ≥ 10). Consumer: main.go metrics server
}

// ++++++++++++++++++++++++++ Section: chain_guard +++++++++++++++++++++++++++++++++++++++

// ChainGuardConfig controls the chain integrity checker.
// When enabled, ArxSentinel detects Cloudflare or bogon IPs appearing as client IPs —
// a sign that the proxy chain is misconfigured and real attacker IPs are not reaching the log.
// Writes to WarningsLog (not threat_log) — these are infrastructure alerts, not threats.
type ChainGuardConfig struct {
	Enabled     bool                 `yaml:"enabled"`      // ENV: ARXSENTINEL_CHAIN_GUARD_ENABLED, default false (requires warnings_log to activate)
	WarningsLog string               `yaml:"warnings_log"` // ENV: ARXSENTINEL_CHAIN_GUARD_WARNINGS_LOG, default "" (required if enabled)
	Cloudflare  CloudflareGuardConfig `yaml:"cloudflare"`
	Bogon       BogonGuardConfig     `yaml:"bogon"`
}

// CloudflareGuardConfig controls Cloudflare IP range fetching and caching.
type CloudflareGuardConfig struct {
	Enabled         bool     `yaml:"enabled"`          // default true
	RefreshInterval Duration `yaml:"refresh_interval"` // default 24h
	Sources         []string `yaml:"sources"`          // default: cloudflare.com/ips-v4/ and ips-v6/
}

// BogonGuardConfig controls bogon/RFC1918/CGNAT IP detection.
// Uses a static built-in list — no network fetch required.
type BogonGuardConfig struct {
	Enabled bool `yaml:"enabled"` // default true
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
//   1. Go defaults (defaultConfig)
//   2. YAML file (if present)
//   3. ARXSENTINEL_* environment variables
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

	if err := validateConfig(&cfg); err != nil {
		return cfg, fmt.Errorf("invalid config %q: %w", path, err)
	}

	return cfg, nil
}

// ========================== Env var overrides =========================================

// applyEnvOverrides overlays ARXSENTINEL_* environment variables on top of cfg.
// Convention: ARXSENTINEL_<SECTION>_<FIELD> (uppercase, underscores).
// An empty or unset variable leaves the corresponding field unchanged.
//
// Not overridable via env vars (complex types — configure via YAML):
//   detectors.probe.paths, detectors.noasset.asset_extensions,
//   detectors.overflow.suspicious_params, detectors.useragent.extra_*_patterns,
//   whitelist.bots, whitelist.custom.ua_substrings, streams
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
	// Detailed source overrides (URLs, refresh intervals) are configured via YAML.
	// Enabled flag and warnings_log path can be overridden via env for Docker deployments.
	if err := envBool("ARXSENTINEL_CHAIN_GUARD_ENABLED", &cfg.ChainGuard.Enabled); err != nil {
		return err
	}
	envStr("ARXSENTINEL_CHAIN_GUARD_WARNINGS_LOG", &cfg.ChainGuard.WarningsLog)

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

// validateConfig checks critical fields after yaml.Unmarshal.
// Zero thresholds can occur if config.yaml specifies a scoring: section with
// incomplete fields (yaml.v3 partial merge limitation) — protects against silent misconfiguration.
func validateConfig(cfg *Config) error {
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
	if cfg.Detectors.Crawler.Enabled && cfg.Detectors.Crawler.MinSequential <= 0 {
		return fmt.Errorf("detectors.crawler.min_sequential must be > 0, got %d",
			cfg.Detectors.Crawler.MinSequential)
	}
	if cfg.Detectors.Bruteforce.Enabled && cfg.Detectors.Bruteforce.MinRequests <= 0 {
		return fmt.Errorf("detectors.bruteforce.min_requests must be > 0, got %d",
			cfg.Detectors.Bruteforce.MinRequests)
	}
	if cfg.Detectors.NoAsset.Enabled && cfg.Detectors.NoAsset.MinPageRequests <= 0 {
		return fmt.Errorf("detectors.noasset.min_page_requests must be > 0, got %d",
			cfg.Detectors.NoAsset.MinPageRequests)
	}
	if cfg.Detectors.Overflow.Enabled && cfg.Detectors.Overflow.MaxURLLength <= 0 {
		return fmt.Errorf("detectors.overflow.max_url_length must be > 0, got %d",
			cfg.Detectors.Overflow.MaxURLLength)
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
	for i, s := range cfg.Streams {
		if s.LogFile == "" {
			return fmt.Errorf("streams[%d].log_file must not be empty", i)
		}
		if s.ThreatLog == "" {
			return fmt.Errorf("streams[%d].threat_log must not be empty", i)
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
		// Sources and refresh schedule are separate from badbot detector config (D6, Flow #025):
		// the detector only decides *what* to match; the manager decides *where* to fetch from.
		Blocklist: blocklist.Config{
			Storage: "",
			Lists: []blocklist.ListConfig{
				{
					Name:            "badbot-ua",
					RefreshInterval: blocklist.Duration(24 * time.Hour),
					Sources: []blocklist.SourceConfig{{
						URL:    "https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/master/_generator_lists/bad-user-agents.list",
						Format: "plain_text",
					}},
				},
				{
					Name:            "badbot-ref",
					RefreshInterval: blocklist.Duration(24 * time.Hour),
					Sources: []blocklist.SourceConfig{{
						URL:    "https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/master/_generator_lists/bad-referrer-words.list",
						Format: "plain_text",
					}},
				},
			},
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
			Name:         "gptbot",
			UAPatterns:   []string{"GPTBot"},
			RDNSDomains:  []string{".openai.com"},
			VerifyMethod: "rdns",
		},
		{
			Name:         "claudebot",
			UAPatterns:   []string{"ClaudeBot", "Claude-Web", "anthropic-ai"},
			RDNSDomains:  []string{".anthropic.com"},
			VerifyMethod: "rdns",
		},
	}
}
