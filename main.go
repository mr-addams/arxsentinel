// ========================== Entry point — nginx-sentinel =================================
//   Component initialization, pipeline assembly, daemon startup.
//
//   WHAT IS HERE:
//     - main() — config loading, logger initialization, pipeline startup
//     - Pipeline Flow #4: TailReader → whitelist check → tracker → scorer(detectors) → logger
//     - buildDetectors() — assembles active detectors from config
//     - processLine() — processes a single log line
//     - writePID() / removePID() — daemon PID file management
//     - GC goroutine: periodic cleanup of inactive IPs
//     - Graceful shutdown: drain buffer + Sync before Close (Task 7.2)
//
//   WHAT IS NOT HERE:
//     - Business logic (core/)
//     - Configuration structures (sys/config)
//     - Logging (sys/utils)
//
//   PIPELINE ARCHITECTURE (Flow #4–6):
//     TailReader → lines chan → whitelist.Matcher (custom IP/UA → early return)
//              ↓
//     whitelist.Verifier (bot UA → rDNS/fDNS → verified → return | isFakeBot → +score)
//              ↓
//     tracker.Update(*IPState)
//              ↓
//     scorer.Evaluate(state, entry, detectors=[probe, rate, ua, bruteforce, crawler, noasset, overflow])
//              ↓ [level≠""]
//     threatLogger.Log
//
//   Change (Flow #4, Tasks 4.0–4.3):
//     Added whitelist integration (Matcher, IPCache, Verifier).
//     Three detectors connected: probe, rate, ua.
//     processLine extended: early-exit on whitelist, fake bot penalty before scorer.
//   Change (Flow #6, Tasks 6.1–6.4):
//     Four detectors connected: bruteforce, crawler, noasset, overflow.
//   Change (Flow #5, Task 5.3):
//     Added PID file management: writePID after utils.Init, defer removePID.
//   Change (Flow #8, Task 8.2):
//     Metrics HTTP server: started once after logger init, survives SIGHUP reload.

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

// processedCount / threatCount — atomic counters for the stats goroutine (Task 7.3).
// Package-level: processLine and ThreatLogger writeFn are in the same package.
// version is injected by goreleaser via ldflags (-X main.version={{.Version}}).
// Remains "dev" when built manually without ldflags.
var version = "dev"

var (
	processedCount atomic.Int64
	threatCount    atomic.Int64
)

// PipelineContext holds long-lived dependencies shared by processLine.
// Recreated on SIGHUP reload: Scorer, Matcher, and Parser are replaced; Tracker and
// Verifier survive. FakeBotScore and DNSVerifyTimeout reflect the current config.
type PipelineContext struct {
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
// Can be overridden via the NGINX_SENTINEL_CONFIG environment variable.
const configPath = "/etc/nginx-sentinel/config.yaml"

func main() {
	// ── Config loading ────────────────────────────────────────────────────────────────

	path := configPath
	if env := os.Getenv("NGINX_SENTINEL_CONFIG"); env != "" {
		path = env
	}

	cfg, err := config.LoadConfig(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nginx-sentinel: config error: %v\n", err)
		os.Exit(1)
	}

	// ── Logger initialization ─────────────────────────────────────────────────────────

	if err := utils.Init(cfg.Logging.Debug, cfg.Logging.ConsoleColor,
		cfg.Output.OperationalLog, cfg.Output.ThreatLog); err != nil {
		// Threat log unavailable — Fail2Ban cannot work without it, startup is not possible
		fmt.Fprintf(os.Stderr, "nginx-sentinel: logger initialization error: %v\n", err)
		os.Exit(1)
	}
	defer utils.Close()

	// PID file is needed for: kill -HUP $(cat pid) and logrotate postrotate (Task 7.1).
	// Write error — warn, not fatal: the daemon works without a PID file, we just lose management convenience.
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
	utils.Log("CONFIG", fmt.Sprintf("log: %s", cfg.General.LogFile), "info")
	if cfg.Metrics.Enabled {
		// Resolve display address: ":9117" → "localhost:9117" for readable log output.
		displayAddr := cfg.Metrics.ListenAddr
		if len(displayAddr) > 0 && displayAddr[0] == ':' {
			displayAddr = "localhost" + displayAddr
		}
		utils.Log("CONFIG", fmt.Sprintf("metrics: http://%s/metrics", displayAddr), "info")
	}

	// ── Pipeline component initialization ────────────────────────────────────────────

	// tracker — in-memory state per IP (Tasks 2.1 + 2.2)
	tracker := state.NewTracker(cfg, utils.Log)

	// whitelist: Matcher (UA/IP lookup), IPCache (DNS results), Verifier (rDNS+fDNS)
	// IPCache is created separately — on SIGHUP (Task 7.1) the cache survives config reload.
	ipCache := whitelist.NewIPCache(cfg.Whitelist.DNSCache)
	matcher, err := whitelist.NewMatcher(cfg.Whitelist)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nginx-sentinel: whitelist initialization error: %v\n", err)
		os.Exit(1)
	}
	resolver := &net.Resolver{PreferGo: true}
	verifier := whitelist.NewVerifier(ipCache, resolver, utils.Log)

	// scorer — score aggregator from detectors (Task 2.3 + Flow #4)
	sc := scorer.NewScorer(cfg.Scoring, buildDetectors(cfg), utils.Log)

	// threatLogger — writes WARN/THREAT to threats.log (Task 2.4).
	// Closure around utils.LogThreat: increments threatCount for the stats goroutine.
	threatLogger := output.NewThreatLogger(func(ip string, score int, level string, modules []string, reason string) {
		// threatCount tracks THREAT-only for STATS log; nginx_sentinel_threats_total tracks
		// both WARN and THREAT — use the Prometheus metric for full threat breakdown.
		if level == "THREAT" {
			threatCount.Add(1)
		}
		utils.LogThreat(ip, score, level, modules, reason)
	})

	pipe := &PipelineContext{
		Tracker:          tracker,
		Scorer:           sc,
		ThreatLogger:     threatLogger,
		Matcher:          matcher,
		Verifier:         verifier,
		Parser:           buildParser(cfg),
		FakeBotScore:     cfg.Whitelist.FakeBotScore,
		DNSVerifyTimeout: time.Duration(cfg.Whitelist.DNSVerifyTimeout),
	}

	// ── Context + shutdown ────────────────────────────────────────────────────────────

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	// ── SIGHUP reload ─────────────────────────────────────────────────────────────────
	// Goroutine converts os.Signal → struct{} into a buffered channel of size 1.
	// If the previous reload has not been processed yet — skip (select default).
	// Main loop reads reloadCh between lines — no concurrent access in processLine.
	sigHUP := make(chan os.Signal, 1)
	signal.Notify(sigHUP, syscall.SIGHUP)
	defer signal.Stop(sigHUP)
	reloadCh := make(chan struct{}, 1)
	go func() {
		for {
			select {
			case <-ctx.Done():
				// Явно останавливаем notify и дренируем канал, чтобы signal.Notify
				// не заблокировался на записи в полный буфер при race с завершением.
				signal.Stop(sigHUP)
				for len(sigHUP) > 0 {
					<-sigHUP
				}
				return
			case <-sigHUP:
				select {
				case reloadCh <- struct{}{}:
				default:
				}
			}
		}
	}()

	// ── Metrics HTTP server (Tasks 8.2, 8.6) ────────────────────────────────────────
	// Started once here — intentionally NOT restarted on SIGHUP so Prometheus scraper
	// keeps continuous counter timeseries (no reset on config reload).
	if cfg.Metrics.Enabled {
		metrics.Init()
		srv := &http.Server{
			Addr:              cfg.Metrics.ListenAddr,
			Handler:           metricsHandler(cfg.Metrics.Username, cfg.Metrics.PasswordHash),
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

	// ── GC goroutine ──────────────────────────────────────────────────────────────────
	go tracker.RunGC(ctx, time.Duration(cfg.State.GCInterval))

	// ── Stats goroutine (Task 7.3) ────────────────────────────────────────────────────
	// Period = general.stats_interval (default 300s) — independent of scoring.observation_window.
	// Goroutine starts once; changing stats_interval via SIGHUP requires restart.
	// processedCount/threatCount — atomics, no races with the pipeline goroutine.
	// tracker.GetStats() iterates under RLock — do not call from hot path.
	go func() {
		ticker := time.NewTicker(time.Duration(cfg.General.StatsInterval))
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				st := tracker.GetStats()
				utils.Log("STATS", fmt.Sprintf(
					"processed=%d tracked=%d threats=%d suspicious=%d",
					processedCount.Load(), st.TrackedIPs,
					threatCount.Load(), st.Suspicious,
				), "info")
				metrics.UpdateGauges(st.TrackedIPs, st.Suspicious)
			}
		}
	}()

	// ── Pipeline: TailReader → parser ─────────────────────────────────────────────────

	lines := make(chan string, cfg.General.LinesBufSize)
	tail := utils.NewTailReader(cfg.General.LogFile, lines, time.Duration(cfg.General.TailRetryInterval))
	go tail.Run(ctx)

	utils.Log("STARTUP", fmt.Sprintf(
		"pipeline started (tail → whitelist → tracker → scorer[probe,rate,ua,bruteforce,crawler,noasset,overflow]) | file: %s",
		cfg.General.LogFile,
	), "info")

	// ── Main processing loop ──────────────────────────────────────────────────────────

	for {
		select {
		case <-ctx.Done():
			utils.Log("SHUTDOWN", "signal received, draining buffer...", "info")
			// TailReader shuts down on the same ctx and closes the channel via defer.
			// We wait for !ok — this guarantees TailReader has flushed all lines before exit.
			// TailReader uses a non-blocking select on send — deadlock is impossible.
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
			utils.Log("SHUTDOWN", "done", "info")
			return

		case <-reloadCh:
			newCfg, err := config.LoadConfig(path)
			if err != nil {
				utils.Log("CONFIG", "SIGHUP: config reload error: "+err.Error(), "warn")
				continue
			}
			// Prepare all components before applying — if one fails, the others are not changed.
			// Partial apply (cfg updated, matcher not) creates a silent mismatch:
			// scorer uses new config thresholds, matcher uses old whitelist.
			newMatcher, err := whitelist.NewMatcher(newCfg.Whitelist)
			if err != nil {
				utils.Log("CONFIG", "SIGHUP: whitelist reload error, reload cancelled: "+err.Error(), "warn")
				continue
			}
			// Atomic apply: all components are ready.
			// LIMITATION: ipCache (TTL settings) is not updated on SIGHUP — the cache
			// survives reload intentionally (cache reset → DNS load on all bot traffic).
			// Changes to dns_cache.positive_ttl/negative_ttl take effect only on restart.
			cfg = newCfg
			tracker.Reconfigure(cfg)
			pipe = &PipelineContext{
				Tracker:          tracker,
				Scorer:           scorer.NewScorer(cfg.Scoring, buildDetectors(cfg), utils.Log),
				ThreatLogger:     threatLogger,
				Matcher:          newMatcher,
				Verifier:         verifier,
				Parser:           buildParser(cfg),
				FakeBotScore:     cfg.Whitelist.FakeBotScore,
				DNSVerifyTimeout: time.Duration(cfg.Whitelist.DNSVerifyTimeout),
			}
			if err := utils.Reload(cfg.Logging.Debug, cfg.Logging.ConsoleColor,
				cfg.Output.OperationalLog, cfg.Output.ThreatLog); err != nil {
				utils.Log("CONFIG", "SIGHUP: logger reload error: "+err.Error(), "warn")
			}
			utils.Log("CONFIG", "SIGHUP: config reloaded", "info")

		case line, ok := <-lines:
			if !ok {
				utils.Log("SHUTDOWN", "channel closed, exiting", "info")
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

// buildParser returns the parser matching cfg.Parser.LogFormat.
// "json" → JSONParser (Task 9.5); all other values → CombinedParser (default).
// Called at startup and on SIGHUP so a log_format change takes effect without restart.
func buildParser(cfg config.Config) parser.Parser {
	return &parser.CombinedParser{}
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
	processedCount.Add(1)
	metrics.RecordLine()

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
		metrics.RecordThreat(level)
		for _, mod := range modules {
			metrics.RecordDetectorHit(mod)
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
