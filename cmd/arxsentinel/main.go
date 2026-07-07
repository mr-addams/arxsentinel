// ========================== Entry point — arxsentinel ====================================
//
//	Component initialization, pipeline assembly, daemon startup.
//
//	WHAT IS HERE:
//	  - main()                          — config load, logger init, metrics server, stream startup
//
//	OTHER FILES IN THE PACKAGE:
//	  - pipeline.go                     — SharedResources (singleton container)
//	  - processor_security.go           — securityProcessor.Process (verbatim port of processLine)
//	  - processor_factory.go            — securityFactory implements runtime.LineProcessorFactory + runtime.LineProcessor
//	  - runtime_adapter.go              — adaptConfigToStreams: config.Config → []runtime.StreamSpec
//	  - builders.go                     — buildSources, buildSinks, buildParserForInput, buildPipelineDetectors
//	  - executors.go                    — startExecutors, preRegisterExecutorQueues
//	  - helpers.go                      — helper functions: parseFlag*, PID, sdNotify, metricsHandler
//	  - validate.go                     — validateConfig (pipeline wiring validation)
//	  - cleanup.go                      — cleanup subcommand
//	  - license.go                      — license subcommand
//
//	RUNTIME (Flow 081 Phase 3):
//	  All stream orchestration (fan-in / dispatch / drain / SIGHUP-reload) has been
//	  moved to arx-core/pkg/runtime. main.go now only assembles StreamSpecs via
//	  runtime_adapter.adaptConfigToStreams and runs coreruntime.Run on each stream,
//	  passing securityFactory and reloadCh. See ADR-004.
//
//	STARTUP SEQUENCE (the order is mandatory — violations lead to panics or data loss):
//	  0. signal.NotifyContext()           — THE VERY FIRST line of main(), before flag.Parse()/
//	     LoadConfig()/utils.Init(). A SIGTERM arriving BEFORE the handler is registered
//	     kills the process through the default OS behavior (no graceful path, no 0 exit
//	     code) — Flow 093 Group H caught this (TestDistributedNCS_CleanShutdown).
//	     Registering as the first line shrinks the vulnerable window to a minimum rather
//	     than eliminating it entirely (signal.Notify physically cannot fire before the
//	     first executable instruction of the process).
//	  1. config.LoadConfig()              — every component depends on cfg
//	  2. utils.Init()                     — the logger must be ready before any Log()
//	  3. writePID()                       — after the logger, so errors land in the log
//	  4. metrics.Init() + srv.ListenAndServe() — before streams; scraper gets continuous series
//	  5. blocklist.NewManager()           — before buildDetectors(); detectors depend on it
//	  6. chaincheck.NewChecker()          — before streams; it inspects every log record from the start
//	  7. coreruntime.Run() × N            — last; every shared resource must already exist
//
//	SHUTDOWN SEQUENCE (SIGTERM/SIGINT → ctx.Done()):
//	  1. tail.Run() exits                — closes the lines channel
//	  2. drainLoop completes             — every buffered line has been processed
//	  3. coreruntime.Run returns → wg.Done() — stream fully finished
//	  4. metricsWg.Wait()                — HTTP server Shutdown() finished (5s timeout)
//	  5. wg.Wait() in main()             — every stream confirmed finished
//	  6. defers LIFO: cancel() → removePID() → utils.Close()
//
//	INVARIANTS:
//	  - No goroutine ever starts with context.Background() — all use appCtx or a derived one
//	  - Every goroutine that holds resources is tracked in a WaitGroup
//	  - SIGHUP is never raced against line processing — both live in the same select goroutine per stream
package main

//go:generate go run github.com/mr-addams/arxsentinel/tools/gen-plugins -profiles ../../profiles -out .

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	ncs "github.com/mr-addams/arx-core/pkg/ncs"
	coreruntime "github.com/mr-addams/arx-core/pkg/runtime"
	"github.com/mr-addams/arxsentinel/internal/core/blocklist"
	"github.com/mr-addams/arxsentinel/internal/core/chaincheck"
	"github.com/mr-addams/arxsentinel/internal/core/output"
	"github.com/mr-addams/arxsentinel/internal/core/state"
	"github.com/mr-addams/arxsentinel/internal/core/whitelist"
	"github.com/mr-addams/arxsentinel/internal/sys/config"
	"github.com/mr-addams/arxsentinel/internal/sys/metrics"
	"github.com/mr-addams/arxsentinel/internal/sys/utils"
)

// version is injected by goreleaser via ldflags (-X main.version={{.Version}}).
// Stays "dev" on a manual build without ldflags.
var version = "dev"

// configPath is the path to the default configuration file.
// Absolute path: when run via systemd with WorkingDirectory=/ the relative
// "./config.yaml" will not be found. Matches the path used in install.sh.
// Can be overridden via the ARXSENTINEL_CONFIG environment variable.
const configPath = "/etc/arxsentinel/config.yaml"

func main() {
	// ── Signal handling — FIRST, before any other work ────────────────────────────────
	// Registered before flag parsing / config loading / logger init so a SIGTERM that
	// arrives during startup is caught by signal.NotifyContext instead of falling through
	// to the OS default disposition (immediate kill, no graceful path, no drained
	// goroutines — Flow 093 Group H's TestDistributedNCS_CleanShutdown caught this: a
	// SIGTERM sent before this call used to terminate the process with no clean exit).
	// Config-loading errors below still exit via os.Exit (fast, nothing running yet to
	// drain) — this ctx only needs to exist EARLY enough that a signal arriving during
	// the (now very short) window before it's registered is vanishingly unlikely, and
	// every goroutine started later in main() observes ctx.Done() correctly regardless
	// of how early in the synchronous setup the underlying signal was received.
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	// ── Subcommand dispatch ───────────────────────────────────────────────────────────
	if len(os.Args) > 1 && os.Args[1] == "cleanup" {
		handleCleanup(os.Args[2:])
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "license" {
		runLicenseSubcommand()
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "validate" {
		// Resolve --config manually before flag.Parse() to reuse the same logic.
		// Both forms are accepted: "--config=path" and "--config path" (space-separated);
		// the latter previously fell back to the default path without a message.
		path := configPath
		args := os.Args[2:]
		for i := 0; i < len(args); i++ {
			if p, ok := strings.CutPrefix(args[i], "--config="); ok {
				path = p
			} else if args[i] == "--config" && i+1 < len(args) {
				path = args[i+1]
				i++
			}
		}
		runValidateSubcommand(path)
		return
	}

	// ── CLI flags ─────────────────────────────────────────────────────────────────────

	showVersion := flag.Bool("version", false, "print version and exit")
	flag.BoolVar(showVersion, "v", false, "print version and exit (shorthand)")
	// --input=stdin overrides config inputs; useful for pipe/container mode.
	inputFlag := flag.String("input", "", "override input source: stdin")
	// --output=stdout[,format] overrides config outputs; format defaults to fail2ban.
	outputFlag := flag.String("output", "", "override output sink: stdout[,json]")
	// --config overrides the path to the config (alternative to ARXSENTINEL_CONFIG env var).
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

	// Fail-fast: validate plugin + executor wiring compatibility before launching
	// any goroutines. validateConfig() walks the entire NCS graph (Decision D2 of flow 061):
	// type-checks the spine, verifies sink type compatibility, resolves executor
	// channels, and searches for orphan channels (writer without reader). On any
	// failure the daemon refuses to start — better an explicit fail than a silent
	// hang in production.
	if errs := validateConfig(cfg); len(errs) > 0 {
		for _, e := range errs {
			fmt.Fprintf(os.Stderr, "arxsentinel: pipeline validation: %s\n", e)
		}
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "arxsentinel: pipeline validation: OK\n")

	// --input / --output flags fully override the I/O sections in the config.
	// When any of the flags is present, cfg.Streams is replaced with a single CLI-driven stream.
	// Migrate() was already called inside LoadConfig; here we build the pipeline directly
	// so that coreruntime.Run always sees Pipelines != nil.
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
	// The threat log is managed per-stream (the engine writes to every sink from StreamSpec).
	// Pass an empty threatLogPath so that the global utils.LogThreat is never used.
	if err := utils.Init(cfg.Logging.Debug, cfg.Logging.ConsoleColor,
		cfg.Output.OperationalLog, ""); err != nil {
		fmt.Fprintf(os.Stderr, "arxsentinel: logger initialization error: %v\n", err)
		os.Exit(1)
	}
	defer utils.Close()

	// PID file is needed for: kill -HUP $(cat pid) and logrotate postrotate (Task 7.1).
	// A write error is a warn, not fatal: the daemon works without a PID file.
	if err := writePID(cfg.General.PIDFile); err != nil {
		utils.Log("STARTUP", fmt.Sprintf("failed to write PID file %s: %v", cfg.General.PIDFile, err), "warn")
	} else {
		defer removePID(cfg.General.PIDFile)
	}

	// ── Startup messages ──────────────────────────────────────────────────────────────

	utils.Log("STARTUP", "arxsentinel "+version+" starting", "info")
	utils.Log("STARTUP", "cookbook: /usr/share/arxsentinel/cookbook/", "info")
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

	// Log active ARXSENTINEL_* env vars for diagnostics.
	// The user can verify that their env vars were read; misspelled names simply
	// won't appear in this line.
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
	// IPCache outlives SIGHUP-reload — resetting it on reload would trigger DNS
	// queries for every bot IP right after the first request, creating a traffic spike.
	ipCache := whitelist.NewIPCache(cfg.Whitelist.DNSCache)
	resolver := &net.Resolver{PreferGo: true}

	// ── Metrics HTTP server ──────────────────────────────────────────────────────────
	// Started once — intentionally NOT restarted on SIGHUP, so the Prometheus
	// scraper preserves continuous counter series (no reset on config reload).
	//
	// metricsWg tracks the shutdown goroutine so that main() waits for srv.Shutdown()
	// before exiting. Without it, the process could exit while Shutdown is still
	// draining in-flight HTTP requests, causing a connection reset on the Prometheus
	// scraper side.
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
		// Both goroutines are tracked so that metricsWg.Wait() in main() guarantees
		// ListenAndServe has returned and every HTTP connection is closed before exit.
		// Shutdown() first closes listeners (which forces ListenAndServe to return
		// ErrServerClosed), then drains active connections — therefore ListenAndServe
		// always returns before Shutdown(), but we track both explicitly for clarity
		// and auditability of the guarantee.
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
			// deadline for HTTP graceful shutdown, not an already-finished context.
			shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer shutCancel()
			_ = srv.Shutdown(shutCtx)
		}()
	}

	// ── SIGHUP fan-out ────────────────────────────────────────────────────────────────
	// One SIGHUP signal → reload of the operational log (shared) + notification of
	// every stream goroutine.
	sigHUP := make(chan os.Signal, 1)
	signal.Notify(sigHUP, syscall.SIGHUP)
	defer signal.Stop(sigHUP)

	// ── Blocklist Manager (Step 6) ────────────────────────────────────────────────────────
	// Created before streams so that all detectors share a single automata graph.
	// Uses appCtx — refresh goroutines stop on SIGTERM together with the streams.
	// Manager.Update() is invoked from the SIGHUP fan-out below, not per-stream.
	blMgr := blocklist.NewManager(ctx, cfg.Blocklist)
	defer blMgr.Close()

	// ── Chain Integrity Checker (Step 7) ──────────────────────────────────────────────
	// Detects Cloudflare or bogon IPs in the role of client IP in access logs.
	// Must start before streams — every log record is inspected from the start.
	// Both fields are nil when chain_guard.enabled == false; callers do a nil-check.
	var chainChecker *chaincheck.Checker
	var warningsWriter *output.WarningsWriter
	if cfg.ChainGuard.Enabled {
		var wErr error
		warningsWriter, wErr = output.NewWarningsWriter(cfg.ChainGuard.WarningsLog)
		if wErr != nil {
			utils.Log("STARTUP", "failed to open warnings log: "+wErr.Error(), "error")
			return
		}
		// warningsWriter is deferred before chainChecker so that LIFO closes the writer
		// last — any in-flight WriteChainWarning finishes before the file is closed.
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
				// Re-read the operational log from a fresh config.
				newCfg, err := config.LoadConfig(path)
				if err == nil {
					if reloadErr := utils.Reload(newCfg.Logging.Debug, newCfg.Logging.ConsoleColor,
						newCfg.Output.OperationalLog, ""); reloadErr != nil {
						utils.Log("CONFIG", "SIGHUP: logger reload error: "+reloadErr.Error(), "warn")
					}
					// Update the blocklist Manager once for all streams — streams do
					// not call Update themselves; they rebuild the pipeline on top of
					// the updated shared automata.
					// Guard: if SIGTERM and SIGHUP arrive in the same select tick,
					// ctx may already be cancelled. Launching new goroutines with a
					// cancelled context is harmless but pointless — skip the update entirely.
					if ctx.Err() == nil {
						shared.BlocklistManager.Update(ctx, newCfg.Blocklist)
						// Update the chain checker with the new config (sources, intervals).
						// Same ctx.Err() guard: Update launches a goroutine for CF refresh.
						if shared.ChainChecker != nil {
							shared.ChainChecker.Update(ctx, newCfg.ChainGuard.ToChainCheckConfig())
						}
					}
					// WarningsWriter.Reopen() is safe after ctx is cancelled: it only
					// closes/reopens the file, never launches goroutines.
					if shared.WarningsWriter != nil {
						_ = shared.WarningsWriter.Reopen()
					}
				}
				// Notify every stream (non-blocking: skip if the channel is full,
				// which means the previous reload has not been processed by the stream yet).
				for _, ch := range reloadChs {
					select {
					case ch <- struct{}{}:
					default:
					}
				}
			}
		}
	}()

	// ── Distributed NCS transport (Flow 093) ──────────────────────────────────────────
	// Must start BEFORE any queue pre-registration below: RegisterSinkFromConfig's
	// queue.type=transport case resolves the live *transport.Transport via
	// transportbridge.GetDefault, which startTransport populates via SetDefault.
	// No-op (returns nil immediately, no goroutine) when cfg.Transport.Enabled is
	// false — see transport_bootstrap.go.
	var wg sync.WaitGroup
	if err := startTransport(ctx, &cfg, &wg); err != nil {
		utils.Log("STARTUP", "transport startup: "+err.Error(), "error")
		os.Exit(1)
	}

	// ── Pre-register Named Channel Switch queues with non-default backends ─────────────
	// Pre-registration lets a YAML `queue: { type: bbolt, ... }` win over a later
	// AttachWriter call from a sink (fan-in refcount++ on existing names).
	// Sources without `queue:` follow the legacy path: the sink creates its own
	// MemoryQueue on the first AttachWriter. On error — fatal: a silent fallback
	// to memory would surprise the operator after a config error.
	if err := preRegisterExecutorQueues(&cfg); err != nil {
		utils.Log("STARTUP", "executor queue pre-registration: "+err.Error(), "error")
		os.Exit(1)
	}

	// F2/F3 (Flow 093): same pre-registration principle as executor queues above,
	// applied to stream-level sentinel-threat outputs and sentinel inputs whose
	// queue: section requests a transport-backed (or bbolt/redis) NCS name instead
	// of the default in-process MemoryQueue.
	if err := preRegisterSinkQueues(&cfg); err != nil {
		utils.Log("STARTUP", "sink queue pre-registration: "+err.Error(), "error")
		os.Exit(1)
	}
	if err := preRegisterInboundTransportQueues(&cfg); err != nil {
		utils.Log("STARTUP", "inbound queue pre-registration: "+err.Error(), "error")
		os.Exit(1)
	}

	// ── Launch executor goroutines (top-level autonomous, Flow #042) ───────────────────────
	// Executors are assembled from cfg.Executors and connected to the Named Channel Switch
	// sources registered by sentinel-threat sinks inside the stream pipeline (T5).
	// ── Launch streams (Flow 081 Phase 3: runtime.Run + securityFactory) ───────────────

	// MetricsCallbacks adapts runtime callbacks to product metrics.* functions.
	// The engine calls:
	//   - RecordLine(s, p, src, st) on EVERY line BEFORE Process (even on Skip) →
	//     here = RecordLine + RecordInputLine (like the old securityProcessor.Process).
	//   - RecordOutputEvent(s, p, sinkName) — sinkType is computed from the name
	//     via sinkTypeFromName (like the old securityProcessor.Process).
	//   - UpdateGauges — direct pass-through.
	metricsCb := &coreruntime.MetricsCallbacks{
		RecordLine: func(s, p, src, st string) {
			metrics.RecordLine(s, p)
			metrics.RecordInputLine(s, p, src, st)
		},
		RecordThreat:      metrics.RecordThreat,
		RecordDetectorHit: metrics.RecordDetectorHit,
		RecordOutputEvent: func(s, p, sinkName string) {
			metrics.RecordOutputEvent(s, p, sinkName, sinkTypeFromName(sinkName))
		},
		UpdateGauges: func(s, p string, tracked, suspicious int64) {
			metrics.UpdateGauges(s, p, int(tracked), int(suspicious))
		},
	}

	// runtime.SharedResources is an opaque container that the engine passes through
	// to factory.Build. Here we put the same singletons as in the local shared
	// (buildPipelineDetectors → bridgeShared needs them).
	runtimeShared := coreruntime.SharedResources{
		BlocklistManager: shared.BlocklistManager,
		ChainChecker:     shared.ChainChecker,
		WarningsWriter:   shared.WarningsWriter,
		MetricsCallbacks: metricsCb,
	}

	streamSpecs, streamReloadChs, err := adaptConfigToStreams(ctx, cfg)
	if err != nil {
		utils.Log("STARTUP", "stream adaptation error: "+err.Error(), "error")
		os.Exit(1)
	}
	// SIGHUP-fanout: replace the earlier-created reloadChs with the ones that correspond
	// to StreamSpec.Pipelines (same indices — main.go builds reloadChs in the order of cfg.Streams).
	reloadChs = streamReloadChs

	for i, spec := range streamSpecs {
		factory := &securityFactory{
			ctx:        ctx,
			path:       path,
			ipCache:    ipCache,
			resolver:   resolver,
			cfg:        cfg,
			streamName: cfg.Streams[i].Name,
			trackers:   make(map[string]*state.Tracker),
			shared:     runtimeShared,
		}
		wg.Add(1)
		go func(spec coreruntime.StreamSpec, factory *securityFactory, reloadCh <-chan struct{}) {
			defer wg.Done()
			if err := coreruntime.Run(ctx, spec, factory, runtimeShared, reloadCh, utils.Log); err != nil {
				utils.Log("ERROR", fmt.Sprintf("stream %q: runtime.Run error: %v", spec.Name, err), "error")
			}
		}(spec, factory, reloadChs[i])
	}

	// Start executors AFTER the stream goroutines so that sentinel-threat sinks
	// have time to register their Named Channel Switch channels. The short delay
	// gives the pipeline goroutines time to reach engine.runPipeline → buildSinks
	// → AttachWriter before AttachReader.
	var execWg sync.WaitGroup
	if len(cfg.Executors) > 0 {
		go func() {
			time.Sleep(200 * time.Millisecond)
			if err := startExecutors(ctx, &cfg, &execWg); err != nil {
				utils.Log("STARTUP", "executor startup error: "+err.Error(), "error")
			}
		}()
	}

	// Notify systemd that all streams are up and the service is ready.
	// Status= is shown in the `systemctl status` output.
	sdNotify("READY=1\nSTATUS=" + version + " running")

	metricsWg.Wait()
	wg.Wait()
	utils.Log("SHUTDOWN", "all streams done", "info")

	// ── Graceful executor shutdown ──────────────────────────────────────────────────
	// DetachWriter on all NCS sources so that executor Run()-loops exit on the closed channel.
	for _, ec := range cfg.Executors {
		for _, src := range ec.Sources {
			ncs.DetachWriter(src.Name)
		}
	}
	execWg.Wait()
	utils.Log("SHUTDOWN", "all executors done", "info")
}
