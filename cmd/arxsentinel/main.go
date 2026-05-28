// ========================== Entry point — arxsentinel ====================================
//   Component initialization, pipeline assembly, daemon startup.
//
//   WHAT IS HERE:
//     - main() — config loading, logger initialization, metrics server, stream launch
//     - runStream() — per-stream orchestrator: builds TrackerGroup map, launches runPipeline goroutines
//     - runPipeline() — isolated processing unit: sources, detectors, sinks, whitelist, scorer
//     - buildPipelineDetectors() — builds detector list from registry (pkg/detector)
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
//     scorer.Evaluate(state, entry, detectors=[probe, rate, ua, bruteforce, crawler, noasset, overflow, badbot])
//              ↓ [level≠""]
//     threatLogger.Log → per-stream threat file
//
//   Multi-stream: each stream runs its own goroutine set (runStream).
//   Backward compat: general.log_file → single unnamed stream, stream="" label on metrics.
//
//   STARTUP SEQUENCE (order is mandatory — violations cause panic or data loss):
//     1. config.LoadConfig()              — must be first; all other components depend on cfg
//     2. utils.Init()                     — logger must be ready before any Log() call
//     3. writePID()                       — after logger so failures are logged
//     4. signal.NotifyContext()           — context before goroutines that check ctx.Done()
//     5. metrics.Init() + srv.ListenAndServe() — before streams; scraper gets continuous series
//     6. blocklist.NewManager()           — before buildDetectors(); detectors depend on it
//     7. chaincheck.NewChecker()          — before streams; checks every log entry from start
//     8. runStream() × N                  — last; all shared resources must exist
//
//   SHUTDOWN SEQUENCE (SIGTERM/SIGINT → ctx.Done()):
//     1. tail.Run() exits                — closes lines channel
//     2. drainLoop completes             — all buffered lines processed
//     3. runStream returns → wg.Done()  — stream fully done
//     4. metricsWg.Wait()               — HTTP server Shutdown() completes (5s timeout)
//     5. wg.Wait() in main()            — all streams confirmed done
//     6. defers LIFO: cancel() → removePID() → utils.Close()
//
//   INVARIANTS:
//     - No goroutine is started with context.Background() — all use appCtx or derived
//     - Every goroutine holding resources is tracked in a WaitGroup
//     - SIGHUP never races with line processing — both in same select goroutine per stream

package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/mr-addams/arxsentinel/internal/core/blocklist"
	"github.com/mr-addams/arxsentinel/internal/core/chaincheck"
	coreinput "github.com/mr-addams/arxsentinel/internal/core/input"
	"github.com/mr-addams/arxsentinel/internal/core/output"
	"github.com/mr-addams/arxsentinel/internal/core/parser"
	"github.com/mr-addams/arxsentinel/internal/core/scorer"
	"github.com/mr-addams/arxsentinel/internal/core/state"
	"github.com/mr-addams/arxsentinel/internal/core/whitelist"
	"github.com/mr-addams/arxsentinel/internal/sys/config"
	"github.com/mr-addams/arxsentinel/internal/sys/metrics"
	"github.com/mr-addams/arxsentinel/internal/sys/utils"
	pkgdetector "github.com/mr-addams/arxsentinel/pkg/detector"
	pkgexecutor "github.com/mr-addams/arxsentinel/pkg/executor"
	pkgsink "github.com/mr-addams/arxsentinel/pkg/sink"
	pkgsource "github.com/mr-addams/arxsentinel/pkg/source"
	"github.com/mr-addams/arxsentinel/pkg/plugin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// version is injected by goreleaser via ldflags (-X main.version={{.Version}}).
// Remains "dev" when built manually without ldflags.
var version = "dev"

// PipelineContext holds long-lived dependencies shared by processLine.
// Recreated on SIGHUP reload: Scorer and Matcher are replaced; Tracker and Verifier survive.
// Sinks are kept across reloads — FileSink.Reload() handles log rotation in-place.
// FakeBotScore and DNSVerifyTimeout reflect the current config.
// Shared is passed by value — SharedResources fields are pointers, so the copy is cheap
// and any nil-check in processLine correctly reflects the state at pipeline construction.
type PipelineContext struct {
	StreamName       string           // empty string for single-stream (backward compat)
	PipelineName     string           // empty string for auto-wrapped legacy pipelines
	processedCount   *atomic.Int64    // per-pipeline counter, owned by runPipeline
	threatCount      *atomic.Int64    // per-pipeline threat counter, owned by runPipeline
	Tracker          *state.Tracker
	Scorer           *scorer.Scorer
	Sinks            []plugin.Sink     // ordered list of output sinks for this stream
	Executors        []plugin.Executor // ordered list of executors run after sinks; nil when none configured
	Matcher          *whitelist.Matcher
	Verifier         *whitelist.Verifier
	FakeBotScore     int
	DNSVerifyTimeout time.Duration
	Shared           SharedResources  // chain checker, warnings writer — nil-safe when disabled
	SourceName       string           // first source name, e.g. "file:/path" — for ThreatEvent metadata
	SourceType       string           // "file" | "stdin" — for ThreatEvent metadata
}

// SharedResources holds singleton dependencies shared across all streams.
// Created once in main() before streams are launched; passed to buildDetectors.
// Manager.Update() is called on SIGHUP from the fan-out goroutine — per-stream
// SIGHUP handlers only rebuild the pipeline, not the shared blocklist state.
// ChainChecker and WarningsWriter are nil when chain_guard.enabled == false —
// all callers must nil-check before use.
type SharedResources struct {
	BlocklistManager *blocklist.Manager
	ChainChecker     *chaincheck.Checker    // nil if chain_guard disabled
	WarningsWriter   *output.WarningsWriter // nil if chain_guard disabled
}

// configPath — default path to the config file.
// Absolute path: when launched via systemd with WorkingDirectory=/, a relative "./config.yaml"
// would not be found. Matches the path used in install.sh.
// Can be overridden via the ARXSENTINEL_CONFIG environment variable.
const configPath = "/etc/arxsentinel/config.yaml"

func main() {
	// ── CLI flags ─────────────────────────────────────────────────────────────────────

	showVersion := flag.Bool("version", false, "print version and exit")
	flag.BoolVar(showVersion, "v", false, "print version and exit (shorthand)")
	// --input=stdin overrides config inputs; useful for pipe/container mode.
	inputFlag := flag.String("input", "", "override input source: stdin")
	// --output=stdout[,format] overrides config outputs; format defaults to fail2ban.
	outputFlag := flag.String("output", "", "override output sink: stdout[,json]")
	// --config overrides the config file path (alternative to ARXSENTINEL_CONFIG env var).
	configFlag := flag.String("config", "", "path to config file (default: "+configPath+")")
	flag.Parse()

	if *showVersion {
		fmt.Println("arxsentinel " + version)
		os.Exit(0)
	}

	// ── Config loading ────────────────────────────────────────────────────────────────

	path := configPath
	if *configFlag != "" {
		path = *configFlag
	} else if env := os.Getenv("ARXSENTINEL_CONFIG"); env != "" {
		path = env
	}

	cfg, err := config.LoadConfig(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "arxsentinel: config error: %v\n", err)
		os.Exit(1)
	}

	// --input / --output flags override the config I/O sections entirely.
	// When either flag is present, cfg.Streams is replaced by a single CLI-driven stream.
	// Migrate() was already called inside LoadConfig; here we construct the pipeline
	// directly so runStream() always sees Pipelines != nil.
	if *inputFlag != "" || *outputFlag != "" {
		// Unset flags fall back to the already-migrated top-level defaults.
		inputs := cfg.Inputs
		outputs := cfg.Outputs
		if *inputFlag != "" {
			inputs = parseFlagInputs(*inputFlag, cfg)
		}
		if *outputFlag != "" {
			var ferr error
			outputs, ferr = parseFlagOutputs(*outputFlag)
			if ferr != nil {
				fmt.Fprintf(os.Stderr, "arxsentinel: --output flag: %v\n", ferr)
				os.Exit(1)
			}
		}
		cfg.Inputs = inputs
		cfg.Outputs = outputs
		cfg.Streams = []config.StreamConfig{{
			Pipelines: []config.PipelineConfig{{
				Inputs:   inputs,
				Outputs:  outputs,
				Pipeline: cfg.Pipeline,
			}},
		}}
	}

	// ── Logger initialization ─────────────────────────────────────────────────────────
	// Threat log is managed per-stream (runStream opens each stream's file directly).
	// Pass empty threatLogPath so global utils.LogThreat is not used.
	if err := utils.Init(cfg.Logging.Debug, cfg.Logging.ConsoleColor,
		cfg.Output.OperationalLog, ""); err != nil {
		fmt.Fprintf(os.Stderr, "arxsentinel: logger initialization error: %v\n", err)
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

	utils.Log("STARTUP", "arxsentinel "+version+" starting", "info")
	utils.Log("CONFIG", fmt.Sprintf("alert=%d ban=%d window=%v debug=%v",
		cfg.Scoring.AlertThreshold,
		cfg.Scoring.BanThreshold,
		time.Duration(cfg.Scoring.ObservationWindow),
		cfg.Logging.Debug,
	), "info")
	if len(cfg.Streams) == 1 {
		src := streamSourceLabel(cfg.Streams[0], cfg)
		utils.Log("CONFIG", fmt.Sprintf("source: %s", src), "info")
	} else {
		utils.Log("CONFIG", fmt.Sprintf("streams: %d", len(cfg.Streams)), "info")
		for _, s := range cfg.Streams {
			utils.Log("CONFIG", fmt.Sprintf("  stream %q: %s", s.Name, streamSourceLabel(s, cfg)), "info")
		}
	}

	// Log active ARXSENTINEL_* env var overrides for diagnostics.
	// Users can verify their env vars were read; misspelled keys will be absent from this line.
	if envVars := activeEnvOverrides(); len(envVars) > 0 {
		utils.Log("CONFIG", fmt.Sprintf("env overrides: %s", strings.Join(envVars, ", ")), "info")
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
	//
	// metricsWg tracks the shutdown goroutine so main() waits for srv.Shutdown() to finish
	// before exiting. Without it, the process could exit while Shutdown is still draining
	// in-flight HTTP requests, causing connection resets on the Prometheus scraper side.
	var metricsWg sync.WaitGroup
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
		// Both goroutines are tracked so metricsWg.Wait() in main() guarantees that
		// ListenAndServe has returned and all HTTP connections are closed before exit.
		// Shutdown() closes listeners first (causing ListenAndServe to return ErrServerClosed),
		// then drains active connections — so ListenAndServe always returns before Shutdown(),
		// but we track both explicitly to make the guarantee clear and audit-proof.
		metricsWg.Add(1)
		go func() {
			defer metricsWg.Done()
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				utils.Log("METRICS", "server error: "+err.Error(), "warn")
			}
		}()
		metricsWg.Add(1)
		go func() {
			defer metricsWg.Done()
			<-ctx.Done()
			// Fresh context: appCtx is already cancelled here — we need an independent
			// deadline for the HTTP graceful shutdown, not a context that's already done.
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

	// ── Blocklist Manager (Step 6) ────────────────────────────────────────────────────────
	// Created before streams so all detectors share the same pattern automata.
	// Uses appCtx — refresh goroutines stop on SIGTERM alongside streams.
	// Manager.Update() is called from the SIGHUP fan-out below, not per-stream.
	blMgr := blocklist.NewManager(ctx, cfg.Blocklist)
	defer blMgr.Close()

	// ── Chain Integrity Checker (Step 7) ──────────────────────────────────────────────
	// Detects Cloudflare or bogon IPs appearing as client IPs in access logs.
	// Must start before streams — all log entries are checked from the beginning.
	// Both fields are nil when chain_guard.enabled == false; callers nil-check before use.
	var chainChecker *chaincheck.Checker
	var warningsWriter *output.WarningsWriter
	if cfg.ChainGuard.Enabled {
		var wErr error
		warningsWriter, wErr = output.NewWarningsWriter(cfg.ChainGuard.WarningsLog)
		if wErr != nil {
			utils.Log("STARTUP", "failed to open warnings log: "+wErr.Error(), "error")
			return
		}
		// warningsWriter deferred before chainChecker so LIFO closes writer last —
		// any in-flight WriteChainWarning call completes before the file is closed.
		defer func() { _ = warningsWriter.Close() }()
		chainChecker = chaincheck.NewChecker(ctx, cfg.ChainGuard.ToChainCheckConfig())
		defer chainChecker.Close()
	}

	shared := SharedResources{
		BlocklistManager: blMgr,
		ChainChecker:     chainChecker,
		WarningsWriter:   warningsWriter,
	}

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
					// Update blocklist Manager once for all streams — streams do not call Update
					// themselves; they rebuild their pipeline using the updated shared automata.
					// Guard: if SIGTERM and SIGHUP arrive in the same select tick, ctx may
					// already be cancelled. Starting new per-list goroutines with a cancelled
					// context is harmless but wasteful — skip the update entirely.
					if ctx.Err() == nil {
						shared.BlocklistManager.Update(ctx, newCfg.Blocklist)
						// Update chain checker with new config (sources, intervals may change).
						// Same ctx.Err() guard: Update starts a goroutine for CF refresh.
						if shared.ChainChecker != nil {
							shared.ChainChecker.Update(ctx, newCfg.ChainGuard.ToChainCheckConfig())
						}
					}
					// WarningsWriter.Reopen() is safe after ctx cancellation:
					// it only closes/reopens a file, never starts goroutines.
					if shared.WarningsWriter != nil {
						_ = shared.WarningsWriter.Reopen()
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
		go runStream(ctx, path, cfg, streamCfg, ipCache, resolver, reloadChs[i], &wg, shared)
	}

	// Notify systemd that all streams are running and the service is ready.
	// Status= appears in `systemctl status` output.
	sdNotify("READY=1\nSTATUS=" + version + " running")

	metricsWg.Wait()
	wg.Wait()
	utils.Log("SHUTDOWN", "all streams done", "info")
}

// runStream is the per-stream orchestrator.
// It builds a TrackerGroup map, starts GC goroutines for each shared tracker, then
// launches one runPipeline() goroutine per pipeline. Returns when all pipelines exit.
func runStream(
	ctx context.Context,
	path string,
	cfg config.Config,
	streamCfg config.StreamConfig,
	ipCache *whitelist.IPCache,
	resolver *net.Resolver,
	reloadCh <-chan struct{},
	wg *sync.WaitGroup,
	shared SharedResources,
) {
	defer wg.Done()
	// Recover from panics so one crashing stream does not take down other streams.
	defer func() {
		if r := recover(); r != nil {
			utils.Log("ERROR", fmt.Sprintf("stream %q: panic recovered: %v", streamCfg.Name, r), "error")
		}
	}()

	// Build TrackerGroup map — pipelines with the same group share one *state.Tracker.
	// Auto-wrapped legacy pipelines (Name="", TrackerGroup="") all land in group ""
	// and share a single tracker, which is the pre-Task-3 behavior.
	trackers := buildTrackerGroups(cfg, streamCfg)

	// Start one GC goroutine per distinct tracker.
	// Two pipelines in the same group share a tracker — starting two GC goroutines
	// on the same tracker would double the GC rate, which is incorrect.
	for _, tracker := range trackers {
		go tracker.RunGC(ctx, time.Duration(cfg.State.GCInterval))
	}

	// Launch one pipeline per PipelineConfig entry.
	var pipelineWg sync.WaitGroup
	for i, pipeCfg := range streamCfg.Pipelines {
		pipelineWg.Add(1)
		tracker := trackers[resolveTrackerGroup(pipeCfg)]
		go runPipeline(ctx, path, cfg, streamCfg, pipeCfg, i, tracker, ipCache, resolver, reloadCh, &pipelineWg, shared)
	}
	pipelineWg.Wait()
}

// runPipeline runs a single isolated pipeline within a stream.
//
// Owns its Sources, Sinks, Whitelist Matcher/Verifier, and Scorer.
// Shares the Tracker from trackers[resolveTrackerGroup(pipeCfg)] with sibling pipelines
// that have the same tracker_group.
//
// Survives SIGHUP: reloads config, rebuilds Scorer+Matcher, calls FileSink.Reload().
// Sources are NOT restarted on SIGHUP — they run continuously across reloads.
func runPipeline(
	ctx context.Context,
	path string,
	cfg config.Config,
	streamCfg config.StreamConfig,
	pipeCfg config.PipelineConfig,
	pipeIdx int,
	tracker *state.Tracker,
	ipCache *whitelist.IPCache,
	resolver *net.Resolver,
	reloadCh <-chan struct{},
	wg *sync.WaitGroup,
	shared SharedResources,
) {
	defer wg.Done()

	// Per-pipeline counters.
	var processedCount atomic.Int64
	var threatCount atomic.Int64

	logTag := pipelineLogTag(streamCfg.Name, pipeCfg.Name)

	// Per-pipeline whitelist matcher (IP/CIDR/UA rules).
	matcher, err := whitelist.NewMatcher(cfg.Whitelist)
	if err != nil {
		utils.Log("ERROR", fmt.Sprintf("%s: whitelist init error: %v", logTag, err), "error")
		return
	}

	// Verifier uses the shared ipCache — DNS results are not pipeline-specific.
	verifier := whitelist.NewVerifier(ipCache, resolver, utils.Log)

	// Build sources and sinks from the pipeline config.
	sources, err := buildSources(cfg, pipeCfg.Inputs)
	if err != nil {
		utils.Log("ERROR", fmt.Sprintf("%s: source init error: %v", logTag, err), "error")
		return
	}
	sinks, err := buildSinks(pipeCfg.Outputs)
	if err != nil {
		utils.Log("ERROR", fmt.Sprintf("%s: sink init error: %v", logTag, err), "error")
		return
	}
	defer func() {
		for _, sink := range sinks {
			_ = sink.Close()
		}
	}()

	// Executors are optional — empty cfg.Executors is not an error.
	// Executor lifecycle is NOT reset on SIGHUP: executors hold state (ban list, TTL
	// goroutines) that must survive config reloads, same as sinks.
	executors, err := buildExecutors(cfg.Executors)
	if err != nil {
		utils.Log("ERROR", fmt.Sprintf("%s: executor init error: %v", logTag, err), "error")
		return
	}
	defer func() {
		for _, ex := range executors {
			_ = ex.Close()
		}
	}()

	sourceName, sourceType := sourceMetadata(sources)

	// Choose buffer size: pipeline-level override or stream-level default.
	bufSize := int(pipeCfg.Pipeline.BufferSize)
	if bufSize == 0 {
		bufSize = int(cfg.Pipeline.BufferSize)
	}

	pipe := &PipelineContext{
		StreamName:       streamCfg.Name,
		PipelineName:     pipeCfg.Name,
		processedCount:   &processedCount,
		threatCount:      &threatCount,
		Tracker:          tracker,
		Scorer:           scorer.NewScorer(cfg.Scoring, buildPipelineDetectors(cfg, pipeCfg, shared), utils.Log),
		Sinks:            sinks,
		Executors:        executors,
		Matcher:          matcher,
		Verifier:         verifier,
		FakeBotScore:     cfg.Whitelist.FakeBotScore,
		DNSVerifyTimeout: time.Duration(cfg.Whitelist.DNSVerifyTimeout),
		Shared:           shared,
		SourceName:       sourceName,
		SourceType:       sourceType,
	}

	// Stats goroutine — periodic operational log line.
	// Captures processedCount, threatCount, tracker, tag directly —
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
				utils.Log("STATS", fmt.Sprintf(
					"%s processed=%d tracked=%d threats=%d suspicious=%d",
					logTag, processedCount.Load(), st.TrackedIPs, threatCount.Load(), st.Suspicious,
				), "info")
				metrics.UpdateGauges(streamCfg.Name, pipeCfg.Name, st.TrackedIPs, st.Suspicious)
			}
		}
	}()

	// Fan-in all sources into a single entries channel.
	// Sources run in goroutines started by Merge and stop when ctx is cancelled.
	entries := coreinput.Merge(ctx, sources, bufSize)

	utils.Log("STARTUP", fmt.Sprintf(
		"%s: pipeline started (sources=%d sinks=%d) | source: %s",
		logTag, len(sources), len(sinks), sourceName,
	), "info")

	// ── Main processing loop ──────────────────────────────────────────────────────────

	for {
		select {
		case <-ctx.Done():
			utils.Log("SHUTDOWN", fmt.Sprintf("%s: signal received, draining buffer...", logTag), "info")
			// Sources stop on ctx.Done() and Merge closes entries when all sources exit.
			// context.Background() instead of ctx: ctx is already cancelled, so verifyCtx
			// (context.WithTimeout(ctx,...)) would be immediately cancelled → all bots
			// would get isFakeBot=true → false ban entries in threats.log on shutdown.
			for entry := range entries {
				processLine(context.Background(), entry, pipe)
			}
			utils.Log("SHUTDOWN", fmt.Sprintf("%s: done", logTag), "info")
			return

		case <-reloadCh:
			newCfg, err := config.LoadConfig(path)
			if err != nil {
				utils.Log("CONFIG", fmt.Sprintf("%s: SIGHUP reload error: %v", logTag, err), "warn")
				continue
			}
			newMatcher, err := whitelist.NewMatcher(newCfg.Whitelist)
			if err != nil {
				utils.Log("CONFIG", fmt.Sprintf("%s: SIGHUP whitelist error, reload cancelled: %v", logTag, err), "warn")
				continue
			}
			// Find the updated stream config by name; fall back to current if removed.
			newStreamCfg := streamCfg
			for _, s := range newCfg.Streams {
				if s.Name == streamCfg.Name {
					newStreamCfg = s
					break
				}
			}
			newPipeCfg := findPipelineCfg(newStreamCfg, pipeCfg.Name, pipeIdx, pipeCfg)
			// Reload FileSinks for log rotation.
			// Sources are NOT restarted — they run continuously across reloads.
			for _, sink := range pipe.Sinks {
				if fs, ok := sink.(*output.FileSink); ok {
					if reloadErr := fs.Reload(); reloadErr != nil {
						utils.Log("CONFIG", fmt.Sprintf("%s: SIGHUP sink reload error: %v", logTag, reloadErr), "warn")
					}
				}
			}
			streamCfg = newStreamCfg
			pipeCfg = newPipeCfg
			cfg = newCfg
			tracker.Reconfigure(cfg)
			pipe = &PipelineContext{
				StreamName:       streamCfg.Name,
				PipelineName:     pipeCfg.Name,
				processedCount:   &processedCount,
				threatCount:      &threatCount,
				Tracker:          tracker,
				Scorer:           scorer.NewScorer(cfg.Scoring, buildPipelineDetectors(cfg, pipeCfg, shared), utils.Log),
				Sinks:            sinks,     // same sinks — already reloaded above
				Executors:        executors, // same executors — state (ban list, TTL) must survive reload
				Matcher:          newMatcher,
				Verifier:         verifier,
				FakeBotScore:     cfg.Whitelist.FakeBotScore,
				DNSVerifyTimeout: time.Duration(cfg.Whitelist.DNSVerifyTimeout),
				Shared:           shared,
				SourceName:       sourceName, // source identity does not change on SIGHUP
				SourceType:       sourceType,
			}
			utils.Log("CONFIG", fmt.Sprintf("%s: SIGHUP config reloaded", logTag), "info")

		case entry, ok := <-entries:
			if !ok {
				utils.Log("SHUTDOWN", fmt.Sprintf("%s: channel closed, exiting", logTag), "info")
				return
			}
			processLine(ctx, entry, pipe)
		}
	}
}

// ── TrackerGroup helpers ───────────────────────────────────────────────────────────────

// buildTrackerGroups creates one *state.Tracker per unique tracker group in the stream.
// Pipelines that share the same group see the same IP state (shared tracker).
func buildTrackerGroups(cfg config.Config, streamCfg config.StreamConfig) map[string]*state.Tracker {
	groups := make(map[string]*state.Tracker)
	for _, pipeCfg := range streamCfg.Pipelines {
		group := resolveTrackerGroup(pipeCfg)
		if _, exists := groups[group]; !exists {
			groups[group] = state.NewTracker(cfg, utils.Log)
		}
	}
	return groups
}

// resolveTrackerGroup returns the effective tracker group key for a pipeline.
// An empty TrackerGroup means isolated: use the pipeline name as the implicit group.
// Auto-wrapped pipelines (Name="", TrackerGroup="") all resolve to "" and share one tracker,
// which is the pre-Task-3 behavior for single-pipeline streams.
func resolveTrackerGroup(pipeCfg config.PipelineConfig) string {
	if pipeCfg.TrackerGroup != "" {
		return pipeCfg.TrackerGroup
	}
	return pipeCfg.Name // "" for auto-wrapped pipelines → shared tracker per stream
}

// pipelineLogTag returns a human-readable log prefix that includes stream and pipeline names.
// Examples: "stream \"nginx\" pipeline \"api\"", "stream \"nginx\"" (unnamed pipeline).
func pipelineLogTag(streamName, pipelineName string) string {
	if streamName == "" && pipelineName == "" {
		return "(default)"
	}
	if pipelineName == "" {
		return fmt.Sprintf("stream %q", streamName)
	}
	return fmt.Sprintf("stream %q pipeline %q", streamName, pipelineName)
}

// findPipelineCfg locates the pipeline config in a (possibly updated) stream config.
// Named pipelines are matched by name; unnamed (auto-wrapped) by index.
// Returns fallback when the pipeline is not found (e.g. removed from config on SIGHUP).
func findPipelineCfg(streamCfg config.StreamConfig, name string, idx int, fallback config.PipelineConfig) config.PipelineConfig {
	if name != "" {
		for _, p := range streamCfg.Pipelines {
			if p.Name == name {
				return p
			}
		}
		return fallback // named pipeline removed from config — keep old
	}
	if idx < len(streamCfg.Pipelines) {
		return streamCfg.Pipelines[idx]
	}
	return fallback
}

// ── Detector construction ──────────────────────────────────────────────────────────────

// detectorShared adapts main.go's SharedResources to pkgdetector.SharedResources.
// *blocklist.Manager satisfies pkgdetector.Matcher implicitly (has Match(list, text) bool).
type detectorShared struct {
	blocklist pkgdetector.Matcher
}

func (s detectorShared) Blocklist() pkgdetector.Matcher { return s.blocklist }

// bridgeShared wraps SharedResources into the pkgdetector.SharedResources interface.
// Returns nil Blocklist when shared.BlocklistManager is nil.
func bridgeShared(shared SharedResources) pkgdetector.SharedResources {
	return detectorShared{blocklist: shared.BlocklistManager}
}

// buildPipelineDetectors constructs the detector list for a pipeline.
//
// If pipeCfg.Detectors is nil (auto-wrapped legacy pipeline), all registered detectors
// are built from the global cfg.Detectors section — preserving backward compat so that
// detectors.rate.threshold=50 in config.yaml continues to work unchanged.
//
// If pipeCfg.Detectors is set (new pipeline syntax), only the listed detectors are built.
// Unknown detector names are logged as warnings and skipped (forward compat).
func buildPipelineDetectors(cfg config.Config, pipeCfg config.PipelineConfig, shared SharedResources) []plugin.Detector {
	ds := bridgeShared(shared)

	var specs map[string]pkgdetector.DetectorConfig
	if pipeCfg.Detectors == nil {
		// Legacy path: build from global cfg.Detectors, respecting all custom parameters.
		specs = globalDetectorSpecs(cfg)
	} else {
		// New syntax path: build exactly the detectors listed in the pipeline config.
		specs = make(map[string]pkgdetector.DetectorConfig, len(pipeCfg.Detectors))
		for name, dc := range pipeCfg.Detectors {
			specs[name] = pkgdetector.DetectorConfig{
				Enabled: dc.Enabled,
				Params:  dc.Params,
				Exec:    dc.Exec,  // exec plugin binary path (empty for built-in detectors)
			}
		}
	}

	var detectors []plugin.Detector
	var names []string
	for name, spec := range specs {
		d, err := pkgdetector.Build(name, spec, ds)
		if err != nil {
			utils.Log("CONFIG", fmt.Sprintf("detector %q: build error: %v (skipped)", name, err), "warn")
			continue
		}
		if d == nil {
			continue // disabled
		}
		detectors = append(detectors, d)
		names = append(names, d.Name())
	}
	sort.Strings(names)
	utils.Log("CONFIG", fmt.Sprintf("detectors: %d active (%s)",
		len(detectors), strings.Join(names, " ")), "info")
	return detectors
}

// globalDetectorSpecs converts the global cfg.Detectors section into the registry format.
// Used by buildPipelineDetectors for auto-wrapped legacy pipelines (Detectors == nil).
// Preserves all user-configured values so existing configs behave identically after Task 3.
func globalDetectorSpecs(cfg config.Config) map[string]pkgdetector.DetectorConfig {
	d := cfg.Detectors
	return map[string]pkgdetector.DetectorConfig{
		"probe": {Enabled: d.Probe.Enabled, Params: map[string]interface{}{
			"score": d.Probe.Score,
			"paths": d.Probe.Paths,
		}},
		"rate": {Enabled: d.Rate.Enabled, Params: map[string]interface{}{
			"threshold": d.Rate.Threshold,
			"window":    time.Duration(d.Rate.Window).String(),
			"score":     d.Rate.Score,
		}},
		"ua": {Enabled: d.UserAgent.Enabled, Params: map[string]interface{}{
			"scanner_score":             d.UserAgent.ScannerScore,
			"grabber_score":             d.UserAgent.GrabberScore,
			"automation_score":          d.UserAgent.AutomationScore,
			"empty_ua_score":            d.UserAgent.EmptyUAScore,
			"extra_scanner_patterns":    d.UserAgent.ExtraScannerPatterns,
			"extra_grabber_patterns":    d.UserAgent.ExtraGrabberPatterns,
			"extra_automation_patterns": d.UserAgent.ExtraAutomationPatterns,
		}},
		"bruteforce": {Enabled: d.Bruteforce.Enabled, Params: map[string]interface{}{
			"min_requests":    d.Bruteforce.MinRequests,
			"ratio_threshold": d.Bruteforce.RatioThreshold,
			"score":           d.Bruteforce.Score,
		}},
		"crawler": {Enabled: d.Crawler.Enabled, Params: map[string]interface{}{
			"min_sequential": d.Crawler.MinSequential,
			"score":          d.Crawler.Score,
		}},
		"noasset": {Enabled: d.NoAsset.Enabled, Params: map[string]interface{}{
			"min_page_requests":     d.NoAsset.MinPageRequests,
			"asset_ratio_threshold": d.NoAsset.AssetRatioThreshold,
			"score":                 d.NoAsset.Score,
			"asset_extensions":      d.NoAsset.AssetExtensions,
		}},
		"overflow": {Enabled: d.Overflow.Enabled, Params: map[string]interface{}{
			"max_url_length":    d.Overflow.MaxURLLength,
			"suspicious_params": d.Overflow.SuspiciousParams,
			"score":             d.Overflow.Score,
		}},
		"badbot": {Enabled: d.BadBot.Enabled, Params: map[string]interface{}{
			"check_ua":       d.BadBot.CheckUA,
			"check_referrer": d.BadBot.CheckReferrer,
			"score":          d.BadBot.Score,
		}},
	}
}

// buildParserForInput returns the parser for a specific InputConfig.
// Priority: global parser.profile → input.parser → global parser.log_format → combined.
func buildParserForInput(cfg config.Config, input config.InputConfig) (parser.Parser, error) {
	// Global profile overrides everything — same precedence as the old buildParser.
	if cfg.Parser.Profile != "" {
		factory, ok := parser.Profiles[cfg.Parser.Profile]
		if !ok {
			return nil, fmt.Errorf("unknown parser profile %q; available: %s",
				cfg.Parser.Profile, parser.AvailableProfiles())
		}
		return factory()
	}
	format := input.Parser
	if format == "" {
		format = cfg.Parser.LogFormat
	}
	switch format {
	case "json":
		return parser.NewJSONParser(cfg.Parser.JSONFields), nil
	case "regex":
		return parser.NewRegexParser(cfg.Parser.RegexPattern)
	default: // "combined", "" → combined
		return &parser.CombinedParser{}, nil
	}
}

// buildSources constructs the Source list from an explicit inputs slice.
// Called from runPipeline with pipeCfg.Inputs — each pipeline owns its inputs directly.
func buildSources(cfg config.Config, inputs []config.InputConfig) ([]plugin.Source, error) {
	if len(inputs) == 0 {
		return nil, fmt.Errorf("no inputs configured")
	}
	sources := make([]plugin.Source, 0, len(inputs))
	for _, in := range inputs {
		p, err := buildParserForInput(cfg, in)
		if err != nil {
			return nil, fmt.Errorf("input %q: %w", in.Type, err)
		}
		src, err := pkgsource.Build(in.Type, pkgsource.InputConfig{
			Type: in.Type,
			Path: in.Path,
			Exec: in.Exec,  // NEW
		}, pkgsource.BuildOptions{
			Parser:        p,
			RetryInterval: time.Duration(cfg.General.TailRetryInterval),
			LogFn:         utils.Log,
		})
		if err != nil {
			return nil, fmt.Errorf("source %q: %w", in.Type, err)
		}
		sources = append(sources, src)
	}
	return sources, nil
}

// buildExecutors constructs the Executor list from the config.Executors section.
// Returns (nil, nil) when the list is empty — executors are optional; an empty
// section does not change pipeline behaviour.
func buildExecutors(items []config.ExecutorItem) ([]plugin.Executor, error) {
	if len(items) == 0 {
		return nil, nil
	}
	executors := make([]plugin.Executor, 0, len(items))
	for _, item := range items {
		ex, err := pkgexecutor.Build(pkgexecutor.ExecutorConfig{
			Name:   item.Name,
			Type:   item.Type,
			Exec:   item.Exec,
			Params: item.Params,
			Config: item.Config,
		})
		if err != nil {
			return nil, fmt.Errorf("executor %q: %w", item.Name, err)
		}
		executors = append(executors, ex)
	}
	return executors, nil
}

// buildSinks constructs the Sink list from an explicit outputs slice.
// Called from runPipeline with pipeCfg.Outputs — each pipeline owns its sinks directly.
func buildSinks(outputs []config.SinkConfig) ([]plugin.Sink, error) {
	if len(outputs) == 0 {
		return nil, fmt.Errorf("no outputs configured")
	}
	sinks := make([]plugin.Sink, 0, len(outputs))
	for _, out := range outputs {
		sink, err := pkgsink.Build(pkgsink.SinkConfig{
			Type:   out.Type,
			Path:   out.Path,
			Format: out.Format,
			Exec:   out.Exec,  // NEW
		})
		if err != nil {
			return nil, fmt.Errorf("sink %q: %w", out.Type, err)
		}
		sinks = append(sinks, sink)
	}
	return sinks, nil
}

// sourceMetadata returns the name and type of the first source for ThreatEvent metadata.
// With multiple sources merged, Phase 1 uses the first source's identity as the stream label.
func sourceMetadata(sources []plugin.Source) (name, sourceType string) {
	if len(sources) == 0 {
		return "", ""
	}
	name = sources[0].Name()
	if strings.HasPrefix(name, "file:") {
		return name, "file"
	}
	return name, "stdin"
}

// sinkTypeFromName extracts the sink type string from a sink Name() value.
// "file:/path/…" → "file", "stdout" → "stdout".
func sinkTypeFromName(name string) string {
	if strings.HasPrefix(name, "file:") {
		return "file"
	}
	return name
}

// streamSourceLabel returns a short human-readable source description for startup logging.
// Checks pipelines when top-level inputs are absent (post-migration configs).
func streamSourceLabel(streamCfg config.StreamConfig, cfg config.Config) string {
	inputs := streamCfg.Inputs
	if len(inputs) == 0 && len(streamCfg.Pipelines) > 0 {
		// After Migrate(), inputs live in Pipelines[0].Inputs.
		inputs = streamCfg.Pipelines[0].Inputs
	}
	if len(inputs) == 0 {
		inputs = cfg.Inputs
	}
	if len(inputs) == 0 {
		return "(none)"
	}
	if inputs[0].Type == "stdin" {
		return "stdin"
	}
	return inputs[0].Path
}

// parseFlagInputs converts the --input flag value into an InputConfig slice.
func parseFlagInputs(flagVal string, cfg config.Config) []config.InputConfig {
	switch flagVal {
	case "stdin":
		return []config.InputConfig{{Type: "stdin", Parser: cfg.Parser.LogFormat}}
	default:
		return []config.InputConfig{{Type: "file", Path: flagVal, Parser: cfg.Parser.LogFormat}}
	}
}

// parseFlagOutputs converts the --output flag value into a SinkConfig slice.
// Accepted forms: "stdout", "stdout,json", "stdout,fail2ban".
func parseFlagOutputs(flagVal string) ([]config.SinkConfig, error) {
	parts := strings.SplitN(flagVal, ",", 2)
	sinkType := parts[0]
	format := "fail2ban"
	if len(parts) == 2 {
		format = parts[1]
	}
	switch sinkType {
	case "stdout":
		return []config.SinkConfig{{Type: "stdout", Format: format}}, nil
	default:
		return nil, fmt.Errorf("unknown output type %q; supported: stdout", sinkType)
	}
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

// processLine processes a single parsed log entry:
//
//	whitelist early-exit → tracking → fake bot penalty → scoring → sinks.
//
// The entry is already parsed by the Source — processLine receives a *plugin.LogEntry.
//
// WHITELIST EARLY-EXIT ARCHITECTURE:
//
//	Step 1 — custom whitelist (IP/CIDR/UA)? → return (do not track internal traffic)
//	Step 2 — UA matches bot pattern? → rDNS/fDNS verification (cached in IPCache)
//	Step 3 — verified bot → return (legitimate, do not track)
//	Step 4 — fake bot → tracker.Update + add FakeBotScore BEFORE scorer.Evaluate
//
// KNOWN LIMITATION (Task 7.x): Verify makes a DNS request synchronously in the pipeline goroutine.
// On cache miss a single request blocks the entries channel for a DNS round-trip (~200ms).
// Mitigation: IPCache caches the result — DNS is only done on the first request for a new IP.
// With a targeted attack using bot UA and many unique IPs, delay is possible.
// Maximum wait is bounded by dnsVerifyTimeout (config whitelist.dns_verify_timeout, default 2s).
func processLine(ctx context.Context, entry *plugin.LogEntry, pipe *PipelineContext) {
	pipe.processedCount.Add(1)
	metrics.RecordLine(pipe.StreamName, pipe.PipelineName)
	metrics.RecordInputLine(pipe.StreamName, pipe.PipelineName, pipe.SourceName, pipe.SourceType)

	utils.Log("PARSER", fmt.Sprintf("%s %s %s %d",
		entry.RealIP, entry.Method, entry.Path, entry.Status,
	), "debug")

	// ── Chain integrity check ─────────────────────────────────────────────────────────
	// Runs before detectors. If the client IP is Cloudflare or bogon, the proxy chain
	// is misconfigured — ArxSentinel cannot identify the real attacker IP. We log the
	// warning loudly (file + operational log) but do NOT add to threat log or score,
	// because this is an infrastructure problem, not an attack verdict.
	// RemoteAddr is checked (not RealIP) — it is the raw TCP peer address, which is
	// what ArxSentinel actually received from the network stack.
	if pipe.Shared.ChainChecker != nil && pipe.Shared.WarningsWriter != nil {
		if result := pipe.Shared.ChainChecker.Check(entry.RemoteAddr); result != nil {
			_ = pipe.Shared.WarningsWriter.WriteChainWarning(result, pipe.SourceName)
			utils.Log("CHAIN_WARN",
				fmt.Sprintf("%s-ip-as-client ip=%s cidr=%s source=%s",
					result.Kind, result.IP, result.MatchedCIDR, pipe.SourceName),
				"warning")
		}
	}

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

	// ── Scoring → sinks ──────────────────────────────────────────────────────────────
	// Evaluate: decay accumulated score + run detectors + issue verdict.
	// Returned *IPState implements detector.ScoreAccess.
	level, score, modules, reason := pipe.Scorer.Evaluate(ipState, entry)

	// Write to sinks and record metrics only on WARN or THREAT.
	if level == "" {
		return
	}

	if level == "THREAT" {
		pipe.threatCount.Add(1)
	}
	metrics.RecordThreat(pipe.StreamName, pipe.PipelineName, level)
	for _, mod := range modules {
		metrics.RecordDetectorHit(pipe.StreamName, pipe.PipelineName, mod)
	}

	event := plugin.ThreatEvent{
		Timestamp:  time.Now().UTC(),
		Level:      level,
		Stream:     pipe.StreamName,
		Source:     pipe.SourceName,
		SourceType: pipe.SourceType,
		IP:         entry.RealIP,
		Score:      score,
		Modules:    modules,
		Reason:     reason,
	}
	utils.Log("THREAT", fmt.Sprintf("%s score=%d modules=%s reason=%q",
		entry.RealIP, score, strings.Join(modules, ","), reason), "warning")
	for _, sink := range pipe.Sinks {
		if err := sink.Write(event); err != nil {
			utils.Log("ERROR", fmt.Sprintf("stream %q: sink %s: %v", pipe.StreamName, sink.Name(), err), "error")
			continue
		}
		metrics.RecordOutputEvent(pipe.StreamName, pipe.PipelineName, sink.Name(), sinkTypeFromName(sink.Name()))
	}

	// Executor loop — runs after all sinks have written the event.
	// Errors are logged but do not stop other executors from running.
	for _, ex := range pipe.Executors {
		if err := ex.Execute(ctx, event); err != nil {
			utils.Log("EXECUTOR_ERROR", fmt.Sprintf("stream %q: executor %s: %v", pipe.StreamName, ex.Name(), err), "error")
		}
	}
}

// ========================== systemd notify ===============================================

// sdNotify sends a state notification to systemd via NOTIFY_SOCKET.
// Called once after all streams start: READY=1 marks the service active,
// STATUS= appears in `systemctl status` output.
// No-op when NOTIFY_SOCKET is absent (non-systemd environments, tests).
func sdNotify(state string) {
	socket := os.Getenv("NOTIFY_SOCKET")
	if socket == "" {
		return
	}
	addr := socket
	// Abstract namespace socket: "@" prefix → replace with null byte per sd_notify spec.
	if len(addr) > 0 && addr[0] == '@' {
		addr = "\x00" + addr[1:]
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: addr, Net: "unixgram"})
	if err != nil {
		return
	}
	defer conn.Close()
	_, _ = conn.Write([]byte(state))
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
			w.Header().Set("WWW-Authenticate", `Basic realm="arxsentinel metrics"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		inner.ServeHTTP(w, r)
	})
}

// ========================== Env var diagnostics =========================================

// activeEnvOverrides returns sorted ARXSENTINEL_* keys found in the environment.
// Used at startup to log which env var overrides are active — helps users verify
// their env vars were read. Misspelled or unsupported keys produce no log but also
// no error; the user can spot them missing from the output.
func activeEnvOverrides() []string {
	prefix := "ARXSENTINEL_"
	var vars []string
	for _, e := range os.Environ() {
		if strings.HasPrefix(e, prefix) {
			if idx := strings.IndexByte(e, '='); idx > 0 {
				vars = append(vars, e[:idx])
			}
		}
	}
	sort.Strings(vars)
	return vars
}
