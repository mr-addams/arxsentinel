// ========================== Entry point — nginx-sentinel =================================
//   Component initialization, pipeline assembly, daemon startup.
//
//   WHAT IS HERE:
//     - main() — config loading, logger initialization, metrics server, stream launch
//     - runStream() — complete per-stream pipeline: tail→whitelist→tracker→scorer→logger
//     - buildDetectors() — assembles active detectors from config
//     - processLine() — processes a single log line
//     - writePID() / removePID() — daemon PID file management
//
//   WHAT IS NOT HERE:
//     - Business logic (core/)
//     - Configuration structures (sys/config)
//     - Logging (sys/utils)
//
//   PIPELINE ARCHITECTURE (Flow #4–6, #13):
//     TailReader → lines chan → whitelist.Matcher (custom IP/UA → early return)
//              ↓
//     whitelist.Verifier (bot UA → rDNS/fDNS → verified → return | isFakeBot → +score)
//              ↓
//     tracker.Update(*IPState)
//              ↓
//     scorer.Evaluate(state, entry, detectors=[probe, rate, ua, bruteforce, crawler, noasset, overflow])
//              ↓ [level≠""]
//     threatLogger.Log → per-stream threat file
//
//   Multi-stream: each stream runs its own goroutine set (runStream).
//   Backward compat: general.log_file → single unnamed stream, stream="" label on metrics.

package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/mr-addams/nginx-sentinel/internal/core/detector"
	"github.com/mr-addams/nginx-sentinel/internal/core/output"
	"github.com/mr-addams/nginx-sentinel/internal/core/parser"
	"github.com/mr-addams/nginx-sentinel/internal/core/scorer"
	"github.com/mr-addams/nginx-sentinel/internal/core/state"
	"github.com/mr-addams/nginx-sentinel/internal/core/whitelist"
	"github.com/mr-addams/nginx-sentinel/internal/sys/config"
	"github.com/mr-addams/nginx-sentinel/internal/sys/metrics"
	"github.com/mr-addams/nginx-sentinel/internal/sys/utils"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// version is injected by goreleaser via ldflags (-X main.version={{.Version}}).
// Remains "dev" when built manually without ldflags.
var version = "dev"

// PipelineContext holds long-lived dependencies shared by processLine.
// Recreated on SIGHUP reload: Scorer, Matcher, and Parser are replaced; Tracker and
// Verifier survive. FakeBotScore and DNSVerifyTimeout reflect the current config.
type PipelineContext struct {
	StreamName       string        // empty string for single-stream (backward compat)
	processedCount   *atomic.Int64 // per-stream counter, owned by runStream
	Tracker          *state.Tracker
	Scorer           *scorer.Scorer
	ThreatLogger     *output.ThreatLogger
	Matcher          *whitelist.Matcher
	Verifier         *whitelist.Verifier
	Parser           parser.Parser
	FakeBotScore     int
	DNSVerifyTimeout time.Duration
}

// configPath — default path to the config file.
// Absolute path: when launched via systemd with WorkingDirectory=/, a relative "./config.yaml"
// would not be found. Matches the path used in install.sh.
// Can be overridden via the ARXSENTINEL_CONFIG environment variable.
const configPath = "/etc/arxsentinel/config.yaml"

func main() {
	// ── Config loading ────────────────────────────────────────────────────────────────

	path := configPath
	if env := os.Getenv("ARXSENTINEL_CONFIG"); env != "" {
		path = env
	}

	cfg, err := config.LoadConfig(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nginx-sentinel: config error: %v\n", err)
		os.Exit(1)
	}

	// ── Logger initialization ─────────────────────────────────────────────────────────
	// Threat log is managed per-stream (runStream opens each stream's file directly).
	// Pass empty threatLogPath so global utils.LogThreat is not used.
	if err := utils.Init(cfg.Logging.Debug, cfg.Logging.ConsoleColor,
		cfg.Output.OperationalLog, ""); err != nil {
		fmt.Fprintf(os.Stderr, "nginx-sentinel: logger initialization error: %v\n", err)
		os.Exit(1)
	}
	defer utils.Close()

	// PID file is needed for: kill -HUP $(cat pid) and logrotate postrotate (Task 7.1).
	// Write error — warn, not fatal: the daemon works without a PID file.
	if err := writePID(cfg.General.PIDFile); err != nil {
		utils.Log("STARTUP", fmt.Sprintf("failed to write PID file %s: %v", cfg.General.PIDFile, err), "warn")
	} else {
		defer removePID(cfg.General.PIDFile)
	}

	// ── Startup messages ──────────────────────────────────────────────────────────────

	utils.Log("STARTUP", "nginx-sentinel "+version+" starting", "info")
	utils.Log("CONFIG", fmt.Sprintf("alert=%d ban=%d window=%v debug=%v",
		cfg.Scoring.AlertThreshold,
		cfg.Scoring.BanThreshold,
		time.Duration(cfg.Scoring.ObservationWindow),
		cfg.Logging.Debug,
	), "info")
	if len(cfg.Streams) == 1 {
		utils.Log("CONFIG", fmt.Sprintf("log: %s", cfg.Streams[0].LogFile), "info")
	} else {
		utils.Log("CONFIG", fmt.Sprintf("streams: %d", len(cfg.Streams)), "info")
		for _, s := range cfg.Streams {
			utils.Log("CONFIG", fmt.Sprintf("  stream %q: %s", s.Name, s.LogFile), "info")
		}
	}
	if cfg.Metrics.Enabled {
		displayAddr := cfg.Metrics.ListenAddr
		if len(displayAddr) > 0 && displayAddr[0] == ':' {
			displayAddr = "localhost" + displayAddr
		}
		utils.Log("CONFIG", fmt.Sprintf("metrics: http://%s/metrics  health: http://%s/health", displayAddr, displayAddr), "info")
	}

	// ── Shared whitelist components ──────────────────────────────────────────────────
	// IPCache survives SIGHUP reload — resetting it on reload would trigger DNS requests
	// for all bot IPs on the first request after reload, creating a traffic spike.
	ipCache := whitelist.NewIPCache(cfg.Whitelist.DNSCache)
	resolver := &net.Resolver{PreferGo: true}

	// ── Context + shutdown ────────────────────────────────────────────────────────────

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	// ── Metrics HTTP server ──────────────────────────────────────────────────────────
	// Started once — intentionally NOT restarted on SIGHUP so Prometheus scraper
	// keeps continuous counter timeseries (no reset on config reload).
	if cfg.Metrics.Enabled {
		metrics.Init()
		mux := http.NewServeMux()
		mux.Handle("/metrics", metricsHandler(cfg.Metrics.Username, cfg.Metrics.PasswordHash))
		mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"status":"ok"}`)
		})
		srv := &http.Server{
			Addr:              cfg.Metrics.ListenAddr,
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
		}
		go func() {
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				utils.Log("METRICS", "server error: "+err.Error(), "warn")
			}
		}()
		go func() {
			<-ctx.Done()
			shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer shutCancel()
			_ = srv.Shutdown(shutCtx)
		}()
	}

	// ── SIGHUP fan-out ────────────────────────────────────────────────────────────────
	// One SIGHUP signal → reload operational log (shared) + notify all stream goroutines.
	sigHUP := make(chan os.Signal, 1)
	signal.Notify(sigHUP, syscall.SIGHUP)
	defer signal.Stop(sigHUP)

	reloadChs := make([]chan struct{}, len(cfg.Streams))
	for i := range reloadChs {
		reloadChs[i] = make(chan struct{}, 1)
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-sigHUP:
				// Reload operational log using fresh config.
				newCfg, err := config.LoadConfig(path)
				if err == nil {
					if reloadErr := utils.Reload(newCfg.Logging.Debug, newCfg.Logging.ConsoleColor,
						newCfg.Output.OperationalLog, ""); reloadErr != nil {
						utils.Log("CONFIG", "SIGHUP: logger reload error: "+reloadErr.Error(), "warn")
					}
				}
				// Notify each stream (non-blocking: skip if channel is full,
				// meaning a previous reload is still pending for that stream).
				for _, ch := range reloadChs {
					select {
					case ch <- struct{}{}:
					default:
					}
				}
			}
		}
	}()

	// ── Launch streams ────────────────────────────────────────────────────────────────

	var wg sync.WaitGroup
	for i, streamCfg := range cfg.Streams {
		wg.Add(1)
		go runStream(ctx, path, cfg, streamCfg, ipCache, resolver, reloadChs[i], &wg)
	}

	wg.Wait()
	utils.Log("SHUTDOWN", "all streams done", "info")
}

// runStream runs the complete pipeline for a single stream.
// Each stream gets its own tracker, scorer, whitelist, TailReader, and threat log file.
// Survives SIGHUP via reloadCh — recreates the pipeline components from a fresh config.
// Signals completion to wg when ctx is cancelled and the line buffer is drained.
func runStream(
	ctx context.Context,
	path string,
	cfg config.Config,
	streamCfg config.StreamConfig,
	ipCache *whitelist.IPCache,
	resolver *net.Resolver,
	reloadCh <-chan struct{},
	wg *sync.WaitGroup,
) {
	defer wg.Done()
	// Recover from panics so one stream crashing does not take down all other streams.
	defer func() {
		if r := recover(); r != nil {
			utils.Log("ERROR", fmt.Sprintf("stream %q: panic recovered: %v", streamCfg.Name, r), "error")
		}
	}()

	// Per-stream counters captured by stats goroutine and processLine via PipelineContext.
	var processedCount atomic.Int64
	var threatCount atomic.Int64

	// Per-stream state tracker.
	tracker := state.NewTracker(cfg, utils.Log)

	// Per-stream whitelist matcher (IP/CIDR/UA rules).
	matcher, err := whitelist.NewMatcher(cfg.Whitelist)
	if err != nil {
		utils.Log("ERROR", fmt.Sprintf("stream %q: whitelist init error: %v", streamCfg.Name, err), "error")
		return
	}

	// Verifier uses the shared ipCache — DNS results are not stream-specific.
	verifier := whitelist.NewVerifier(ipCache, resolver, utils.Log)

	// Per-stream threat file.
	threatFile, err := utils.OpenThreatLog(streamCfg.ThreatLog)
	if err != nil {
		utils.Log("ERROR", fmt.Sprintf("stream %q: threat log error: %v", streamCfg.Name, err), "error")
		return
	}
	defer func() { _ = threatFile.Sync(); _ = threatFile.Close() }()

	// makeThreatLogger builds a ThreatLogger whose writeFn writes to tf (a specific file)
	// and mirrors the event to the console. threatCount is incremented for THREAT-level events.
	makeThreatLogger := func(tf *os.File) *output.ThreatLogger {
		return output.NewThreatLogger(func(ip string, score int, level string, modules []string, reason string) {
			if level == "THREAT" {
				threatCount.Add(1)
			}
			line := output.FormatThreatLine(ip, score, level, modules, reason)
			if _, werr := fmt.Fprintln(tf, line); werr != nil {
				fmt.Fprintf(os.Stderr, "[ERROR] stream %q: threat record lost (%s score=%d): %v\n",
					streamCfg.Name, ip, score, werr)
			}
			modulesStr := strings.Join(modules, ",")
			utils.Log("THREAT", fmt.Sprintf("%s score=%d modules=%s reason=%q",
				ip, score, modulesStr, reason), "warning")
		})
	}

	// Build initial pipeline context.
	p, err := buildParser(cfg)
	if err != nil {
		utils.Log("ERROR", fmt.Sprintf("stream %q: parser init error: %v", streamCfg.Name, err), "error")
		return
	}
	pipe := &PipelineContext{
		StreamName:       streamCfg.Name,
		processedCount:   &processedCount,
		Tracker:          tracker,
		Scorer:           scorer.NewScorer(cfg.Scoring, buildDetectors(cfg), utils.Log),
		ThreatLogger:     makeThreatLogger(threatFile),
		Matcher:          matcher,
		Verifier:         verifier,
		Parser:           p,
		FakeBotScore:     cfg.Whitelist.FakeBotScore,
		DNSVerifyTimeout: time.Duration(cfg.Whitelist.DNSVerifyTimeout),
	}

	// GC goroutine — periodic cleanup of inactive IPs.
	// Interval is fixed at startup: RunGC holds the ticker internally.
	// A gc_interval change in config takes effect only on restart.
	go tracker.RunGC(ctx, time.Duration(cfg.State.GCInterval))

	// Stats goroutine — periodic operational log line.
	// Captures processedCount, threatCount, tracker, streamCfg.Name directly —
	// does not access the pipe variable, which may be reassigned on SIGHUP.
	go func() {
		ticker := time.NewTicker(time.Duration(cfg.General.StatsInterval))
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				st := tracker.GetStats()
				prefix := ""
				if streamCfg.Name != "" {
					prefix = fmt.Sprintf("[%s] ", streamCfg.Name)
				}
				utils.Log("STATS", fmt.Sprintf(
					"%sprocessed=%d tracked=%d threats=%d suspicious=%d",
					prefix, processedCount.Load(), st.TrackedIPs, threatCount.Load(), st.Suspicious,
				), "info")
				metrics.UpdateGauges(streamCfg.Name, st.TrackedIPs, st.Suspicious)
			}
		}
	}()

	// TailReader feeds log lines into the lines channel.
	lines := make(chan string, cfg.General.LinesBufSize)
	tail := utils.NewTailReader(streamCfg.LogFile, lines, time.Duration(cfg.General.TailRetryInterval))
	go tail.Run(ctx)

	utils.Log("STARTUP", fmt.Sprintf(
		"stream %q: pipeline started (tail→whitelist→tracker→scorer) | file: %s",
		streamCfg.Name, streamCfg.LogFile,
	), "info")

	// ── Main processing loop ──────────────────────────────────────────────────────────

	for {
		select {
		case <-ctx.Done():
			utils.Log("SHUTDOWN", fmt.Sprintf("stream %q: signal received, draining buffer...", streamCfg.Name), "info")
			// TailReader shuts down on the same ctx and closes the channel via defer.
			// We wait for !ok — this guarantees TailReader has flushed all lines before exit.
			// context.Background() instead of ctx: ctx is already cancelled, so verifyCtx
			// (context.WithTimeout(ctx,...)) would be immediately cancelled → all bots
			// would get isFakeBot=true → false ban entries in threats.log on shutdown.
		drainLoop:
			for {
				line, ok := <-lines
				if !ok {
					break drainLoop
				}
				processLine(context.Background(), line, pipe)
			}
			utils.Log("SHUTDOWN", fmt.Sprintf("stream %q: done", streamCfg.Name), "info")
			return

		case <-reloadCh:
			newCfg, err := config.LoadConfig(path)
			if err != nil {
				utils.Log("CONFIG", fmt.Sprintf("stream %q: SIGHUP reload error: %v", streamCfg.Name, err), "warn")
				continue
			}
			newMatcher, err := whitelist.NewMatcher(newCfg.Whitelist)
			if err != nil {
				utils.Log("CONFIG", fmt.Sprintf("stream %q: SIGHUP whitelist error, reload cancelled: %v", streamCfg.Name, err), "warn")
				continue
			}
			// Find the updated stream config by name.
			// If stream was removed from config, keep the old streamCfg (graceful: finish existing work).
			newStreamCfg := streamCfg
			for _, s := range newCfg.Streams {
				if s.Name == streamCfg.Name {
					newStreamCfg = s
					break
				}
			}
			// Reopen threat file so logrotate can rotate it after sending SIGHUP.
			newThreatFile, err := utils.OpenThreatLog(newStreamCfg.ThreatLog)
			if err != nil {
				utils.Log("CONFIG", fmt.Sprintf("stream %q: SIGHUP threat log error, reload cancelled: %v", streamCfg.Name, err), "warn")
				continue
			}
			_ = threatFile.Sync()
			_ = threatFile.Close()
			threatFile = newThreatFile
			streamCfg = newStreamCfg

			newParser, err := buildParser(newCfg)
			if err != nil {
				utils.Log("CONFIG", fmt.Sprintf("stream %q: SIGHUP parser error, reload cancelled: %v", streamCfg.Name, err), "warn")
				continue
			}
			cfg = newCfg
			tracker.Reconfigure(cfg)
			pipe = &PipelineContext{
				StreamName:       streamCfg.Name,
				processedCount:   &processedCount,
				Tracker:          tracker,
				Scorer:           scorer.NewScorer(cfg.Scoring, buildDetectors(cfg), utils.Log),
				ThreatLogger:     makeThreatLogger(threatFile),
				Matcher:          newMatcher,
				Verifier:         verifier,
				Parser:           newParser,
				FakeBotScore:     cfg.Whitelist.FakeBotScore,
				DNSVerifyTimeout: time.Duration(cfg.Whitelist.DNSVerifyTimeout),
			}
			utils.Log("CONFIG", fmt.Sprintf("stream %q: SIGHUP config reloaded", streamCfg.Name), "info")

		case line, ok := <-lines:
			if !ok {
				utils.Log("SHUTDOWN", fmt.Sprintf("stream %q: channel closed, exiting", streamCfg.Name), "info")
				return
			}
			processLine(ctx, line, pipe)
		}
	}
}

// detectorFactories — registry of all available detectors.
// Each factory returns nil when the detector is disabled in config.
// To add a new detector: append one entry here + write a newXxxDetector function below.
var detectorFactories = []func(config.Config) detector.Detector{
	newProbeDetector,
	newRateDetector,
	newUADetector,
	newBruteforceDetector,
	newCrawlerDetector,
	newNoAssetDetector,
	newOverflowDetector,
}

// buildDetectors assembles the list of active detectors from config.
// Iterates detectorFactories; nil returns (disabled) are filtered out.
func buildDetectors(cfg config.Config) []detector.Detector {
	var detectors []detector.Detector
	var names []string
	for _, f := range detectorFactories {
		if d := f(cfg); d != nil {
			detectors = append(detectors, d)
			names = append(names, d.Name())
		}
	}
	utils.Log("CONFIG", fmt.Sprintf("detectors: %d active (%s)",
		len(detectors), strings.Join(names, " ")), "info")
	return detectors
}

// buildParser returns the parser for the current config.
// Priority: parser.profile → parser.log_format → default combined (Decision 1 — Flow #15).
// Called at startup and on SIGHUP so format changes take effect without restart.
func buildParser(cfg config.Config) (parser.Parser, error) {
	// Profile takes priority over log_format.
	if cfg.Parser.Profile != "" {
		factory, ok := parser.Profiles[cfg.Parser.Profile]
		if !ok {
			return nil, fmt.Errorf("unknown parser profile %q; available: %s",
				cfg.Parser.Profile, parser.AvailableProfiles())
		}
		return factory()
	}
	switch cfg.Parser.LogFormat {
	case "json":
		return parser.NewJSONParser(cfg.Parser.JSONFields), nil
	case "regex":
		return parser.NewRegexParser(cfg.Parser.RegexPattern)
	default:
		return &parser.CombinedParser{}, nil
	}
}

// ── Detector factories ─────────────────────────────────────────────────────────────────

func newProbeDetector(cfg config.Config) detector.Detector {
	if !cfg.Detectors.Probe.Enabled {
		return nil
	}
	return detector.NewProbeDetector(cfg.Detectors.Probe)
}

func newRateDetector(cfg config.Config) detector.Detector {
	if !cfg.Detectors.Rate.Enabled {
		return nil
	}
	return detector.NewRateDetector(cfg.Detectors.Rate)
}

func newUADetector(cfg config.Config) detector.Detector {
	if !cfg.Detectors.UserAgent.Enabled {
		return nil
	}
	return detector.NewUADetector(cfg.Detectors.UserAgent)
}

func newBruteforceDetector(cfg config.Config) detector.Detector {
	if !cfg.Detectors.Bruteforce.Enabled {
		return nil
	}
	return detector.NewBruteforceDetector(cfg.Detectors.Bruteforce)
}

func newCrawlerDetector(cfg config.Config) detector.Detector {
	if !cfg.Detectors.Crawler.Enabled {
		return nil
	}
	return detector.NewCrawlerDetector(cfg.Detectors.Crawler)
}

func newNoAssetDetector(cfg config.Config) detector.Detector {
	if !cfg.Detectors.NoAsset.Enabled {
		return nil
	}
	return detector.NewNoAssetDetector(cfg.Detectors.NoAsset)
}

func newOverflowDetector(cfg config.Config) detector.Detector {
	if !cfg.Detectors.Overflow.Enabled {
		return nil
	}
	return detector.NewOverflowDetector(cfg.Detectors.Overflow)
}

// ========================== PID file ====================================================

// writePID writes the current process PID to a file.
// Used for: kill -HUP $(cat pid) and logrotate postrotate (Task 7.1).
// On error — the caller logs a warn and continues: PID is not critical.
func writePID(path string) error {
	return os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())+"\n"), 0644)
}

// removePID removes the PID file when the daemon exits.
// Called via defer — fires on any return from main, including SIGTERM.
// Error on removal is intentionally ignored: the file may have been deleted manually by an operator.
func removePID(path string) {
	_ = os.Remove(path)
}

// processLine processes a single log line:
//
//	parse → whitelist early-exit → tracking → fake bot penalty → scoring → threat log.
//
// WHITELIST EARLY-EXIT ARCHITECTURE:
//
//	Step 1 — custom whitelist (IP/CIDR/UA)? → return (do not track internal traffic)
//	Step 2 — UA matches bot pattern? → rDNS/fDNS verification (cached in IPCache)
//	Step 3 — verified bot → return (legitimate, do not track)
//	Step 4 — fake bot → tracker.Update + add FakeBotScore BEFORE scorer.Evaluate
//
// KNOWN LIMITATION (Task 7.x): Verify makes a DNS request synchronously in the pipeline goroutine.
// On cache miss a single request blocks the lines channel processing for a DNS round-trip (~200ms).
// Mitigation: IPCache caches the result — DNS is only done on the first request for a new IP.
// With a targeted attack using bot UA and many unique IPs, delay is possible.
// Maximum wait is bounded by dnsVerifyTimeout (config whitelist.dns_verify_timeout, default 2s). On timeout → isFakeBot=true.
//
// Change (Flow #4, Task 4.0): added whitelist integration and fake bot penalty.
func processLine(ctx context.Context, line string, pipe *PipelineContext) {
	entry, ok := pipe.Parser.Parse(line)
	if !ok {
		utils.Log("PARSER", fmt.Sprintf("skipping malformed line: %.80s", line), "debug")
		return
	}
	// Only successfully parsed lines are counted — malformed entries are excluded.
	pipe.processedCount.Add(1)
	metrics.RecordLine(pipe.StreamName)

	utils.Log("PARSER", fmt.Sprintf("%s %s %s %d",
		entry.RealIP, entry.Method, entry.Path, entry.Status,
	), "debug")

	// ── Step 1: custom whitelist early-exit ──────────────────────────────────────────
	// Custom whitelist is checked before tracker.Update — whitelisted traffic does not
	// enter state, reducing GC load and not skewing detector statistics.
	if pipe.Matcher.IsWhitelistedIP(entry.RealIP) || pipe.Matcher.IsWhitelistedUA(entry.UserAgent) {
		utils.Log("WHITELIST", "skipping via custom whitelist: "+entry.RealIP, "debug")
		return
	}

	// ── Steps 2–3: bot detection and verification ────────────────────────────────────
	// MatchBot is fast (strings.Contains over slice). Verify caches the result —
	// DNS request is only made on the first occurrence of a new IP with a bot UA.
	// verifyCtx with timeout: limits pipeline blocking (see KNOWN LIMITATION above).
	isFakeBot := false
	if _, botCfg, matched := pipe.Matcher.MatchBot(entry.UserAgent); matched {
		verifyCtx, cancelVerify := context.WithTimeout(ctx, pipe.DNSVerifyTimeout)
		verified, fake := pipe.Verifier.Verify(verifyCtx, entry.RealIP, botCfg)
		cancelVerify()
		if verified {
			// Legitimate bot confirmed via rDNS/fDNS — do not track, do not score
			utils.Log("WHITELIST", "skipping: verified bot "+entry.RealIP, "debug")
			return
		}
		isFakeBot = fake
	}

	// ── Step 4: IP state tracking ─────────────────────────────────────────────────────
	// Called after whitelist checks — only suspicious IPs enter state.
	ipState := pipe.Tracker.Update(entry)

	// ── Step 4b: fake bot penalty ─────────────────────────────────────────────────────
	// FakeBotScore is added to the accumulated score BEFORE Evaluate.
	//
	// Timestamp = time.Now(): scorer.Evaluate will receive elapsed≈0 → decay≈0% → penalty
	// passes through in full. Inaccuracy: prev is not decayed in this Evaluate cycle,
	// but elapsed between lines of one active IP — seconds within window=300s (<1% error).
	// The next Evaluate correctly decays the entire score from this timestamp.
	//
	// Alternative — manually decay prev before SetScore — duplicates scorer.applyDecay logic
	// and requires passing window into processLine. Deferred to Task 7.x (scorer refactor).
	if isFakeBot {
		ipState.SetScore(ipState.GetScore()+pipe.FakeBotScore, time.Now())
		utils.Log("WHITELIST", fmt.Sprintf("fake bot %s +%d (fake bot score)", entry.RealIP, pipe.FakeBotScore), "warn")
	}

	// ── Scoring → threat log ──────────────────────────────────────────────────────────
	// Evaluate: decay accumulated score + run detectors + issue verdict.
	// Returned *IPState implements detector.ScoreAccess.
	level, score, modules, reason := pipe.Scorer.Evaluate(ipState, entry)

	// Write to threat log and record metrics only on WARN or THREAT.
	if level != "" {
		metrics.RecordThreat(pipe.StreamName, level)
		for _, mod := range modules {
			metrics.RecordDetectorHit(pipe.StreamName, mod)
		}
	}
	pipe.ThreatLogger.Log(entry.RealIP, score, level, modules, reason)
}

// ========================== Metrics auth ================================================

// metricsHandler wraps promhttp.Handler with optional bcrypt basic auth.
// If username is empty, auth is disabled and the handler is returned as-is.
// Both username and password are always compared to prevent timing side-channels.
func metricsHandler(username, passwordHash string) http.Handler {
	inner := promhttp.Handler()
	if username == "" {
		return inner
	}
	usernameBytes := []byte(username)
	hashBytes := []byte(passwordHash)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		// Both checks run unconditionally to avoid timing side-channels.
		userOK := subtle.ConstantTimeCompare([]byte(u), usernameBytes) == 1
		passOK := bcrypt.CompareHashAndPassword(hashBytes, []byte(p)) == nil
		if !ok || !userOK || !passOK {
			w.Header().Set("WWW-Authenticate", `Basic realm="nginx-sentinel metrics"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		inner.ServeHTTP(w, r)
	})
}
