// ========================== Entry point — arxsentinel ====================================
//   Инициализация компонентов, сборка pipeline, запуск демона.
//
//   ЧТО ЗДЕСЬ:
//     - main()                          — загрузка конфига, init логгера, metrics-сервер, запуск стримов
//
//   ДРУГИЕ ФАЙЛЫ ПАКЕТА:
//     - pipeline.go                     — PipelineContext, SharedResources, runStream, runPipeline, processLine
//     - builders.go                     — buildSources, buildSinks, buildParserForInput, buildPipelineDetectors
//     - executors.go                    — startExecutors, preRegisterExecutorQueues
//     - helpers.go                      — вспомогательные функции: parseFlag*, PID, sdNotify, metricsHandler
//     - validate.go                     — validateConfig (валидация pipeline wiring)
//     - cleanup.go                      — подкоманда cleanup
//     - license.go                      — подкоманда license
//
//   STARTUP SEQUENCE (порядок обязателен — нарушения ведут к panic или потере данных):
//     1. config.LoadConfig()              — должен быть первым; все компоненты зависят от cfg
//     2. utils.Init()                     — логгер должен быть готов до любого Log()
//     3. writePID()                       — после логгера, чтобы ошибки попали в лог
//     4. signal.NotifyContext()           — context до горутин, проверяющих ctx.Done()
//     5. metrics.Init() + srv.ListenAndServe() — до стримов; scraper получает непрерывные серии
//     6. blocklist.NewManager()           — до buildDetectors(); детекторы зависят от него
//     7. chaincheck.NewChecker()          — до стримов; проверяет каждую запись лога с начала
//     8. runStream() × N                  — последним; все shared-ресурсы должны существовать
//
//   SHUTDOWN SEQUENCE (SIGTERM/SIGINT → ctx.Done()):
//     1. tail.Run() exits                — закрывает lines-канал
//     2. drainLoop completes             — все буферизованные строки обработаны
//     3. runStream returns → wg.Done()   — стрим полностью завершён
//     4. metricsWg.Wait()                — HTTP-сервер Shutdown() завершён (таймаут 5s)
//     5. wg.Wait() in main()             — все стримы подтверждённо завершены
//     6. defers LIFO: cancel() → removePID() → utils.Close()
//
//   ИНВАРИАНТЫ:
//     - Ни одна горутина не стартует с context.Background() — все используют appCtx или derived
//     - Каждая горутина, удерживающая ресурсы, трекается в WaitGroup
//     - SIGHUP никогда не гонится с обработкой строк — оба в одной select-горутине на стрим

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

// version инжектируется goreleaser через ldflags (-X main.version={{.Version}}).
// Остаётся "dev" при ручной сборке без ldflags.
var version = "dev"

// configPath — путь к файлу конфигурации по умолчанию.
// Абсолютный путь: при запуске через systemd с WorkingDirectory=/ относительный
// "./config.yaml" не будет найден. Совпадает с путём в install.sh.
// Может быть переопределён переменной окружения ARXSENTINEL_CONFIG.
const configPath = "/etc/arxsentinel/config.yaml"

func main() {
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
		// Резолвим --config вручную до flag.Parse(), чтобы переиспользовать ту же логику.
		// Принимаются обе формы: "--config=path" и "--config path" (через пробел);
		// последняя ранее проваливалась на дефолтный путь без сообщения.
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

	// ── CLI флаги ─────────────────────────────────────────────────────────────────────

	showVersion := flag.Bool("version", false, "print version and exit")
	flag.BoolVar(showVersion, "v", false, "print version and exit (shorthand)")
	// --input=stdin переопределяет config inputs; полезно для pipe/container-режима.
	inputFlag := flag.String("input", "", "override input source: stdin")
	// --output=stdout[,format] переопределяет config outputs; format дефолтит в fail2ban.
	outputFlag := flag.String("output", "", "override output sink: stdout[,json]")
	// --config переопределяет путь к конфигу (альтернатива переменной ARXSENTINEL_CONFIG).
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

	// Fail-fast: валидируем совместимость plugin + executor wiring до запуска
	// каких-либо горутин. validateConfig() обходит весь NCS-граф (Decision D2 флоу 061):
	// type-check'ит spine, проверяет type-совместимость sink'ов, резолвит каналы
	// executor'ов и ищет orphan-каналы (writer без reader). При любом сбое
	// демон отказывается стартовать — лучше явный fail, чем тихий hang в проде.
	if errs := validateConfig(cfg); len(errs) > 0 {
		for _, e := range errs {
			fmt.Fprintf(os.Stderr, "arxsentinel: pipeline validation: %s\n", e)
		}
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "arxsentinel: pipeline validation: OK\n")

	// --input / --output флаги полностью переопределяют секции I/O в конфиге.
	// При наличии любого из флагов cfg.Streams заменяется одним CLI-driven стримом.
	// Migrate() уже был вызван внутри LoadConfig; здесь собираем pipeline напрямую,
	// чтобы runStream() всегда видел Pipelines != nil.
	if *inputFlag != "" || *outputFlag != "" {
		// Незаданные флаги откатываются на уже мигрированные top-level дефолты.
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

	// ── Инициализация логгера ─────────────────────────────────────────────────────────
	// Threat-лог управляется per-stream (runStream открывает файл каждого стрима напрямую).
	// Передаём пустой threatLogPath, чтобы глобальный utils.LogThreat не использовался.
	if err := utils.Init(cfg.Logging.Debug, cfg.Logging.ConsoleColor,
		cfg.Output.OperationalLog, ""); err != nil {
		fmt.Fprintf(os.Stderr, "arxsentinel: logger initialization error: %v\n", err)
		os.Exit(1)
	}
	defer utils.Close()

	// PID-файл нужен для: kill -HUP $(cat pid) и logrotate postrotate (Task 7.1).
	// Ошибка записи — warn, не fatal: демон работает и без PID-файла.
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

	// Логируем активные ARXSENTINEL_* env-переменные для диагностики.
	// Пользователь может проверить, что его env-переменные были прочитаны;
	// опечатанные имена просто не появятся в этой строке.
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

	// ── Shared whitelist-компоненты ──────────────────────────────────────────────────
	// IPCache переживает SIGHUP-reload — сброс его на reload вызвал бы DNS-запросы
	// по всем bot-IP сразу после первого запроса, создавая всплеск трафика.
	ipCache := whitelist.NewIPCache(cfg.Whitelist.DNSCache)
	resolver := &net.Resolver{PreferGo: true}

	// ── Context + shutdown ────────────────────────────────────────────────────────────

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	// ── Metrics HTTP-сервер ──────────────────────────────────────────────────────────
	// Запускается один раз — намеренно НЕ перезапускается на SIGHUP, чтобы Prometheus
	// scraper сохранял непрерывные counter-серии (без сброса на config reload).
	//
	// metricsWg трекает shutdown-горутину, чтобы main() дождался srv.Shutdown()
	// перед выходом. Без неё процесс мог бы выйти, пока Shutdown ещё дренирует
	// in-flight HTTP-запросы, вызывая connection reset на стороне Prometheus scraper'а.
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
		// Обе горутины трекаются, чтобы metricsWg.Wait() в main() гарантировал,
		// что ListenAndServe вернулся и все HTTP-соединения закрыты до выхода.
		// Shutdown() сначала закрывает listeners (что заставляет ListenAndServe
		// вернуть ErrServerClosed), затем дренирует активные соединения — поэтому
		// ListenAndServe всегда возвращается до Shutdown(), но мы трекаем оба
		// явно для ясности и аудитируемости гарантии.
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
			// Свежий context: appCtx уже отменён здесь — нужен независимый
			// дедлайн для HTTP graceful shutdown, а не уже завершённый context.
			shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer shutCancel()
			_ = srv.Shutdown(shutCtx)
		}()
	}

	// ── SIGHUP fan-out ────────────────────────────────────────────────────────────────
	// Один SIGHUP-сигнал → reload операционного лога (shared) + нотификация всех
	// stream-горутин.
	sigHUP := make(chan os.Signal, 1)
	signal.Notify(sigHUP, syscall.SIGHUP)
	defer signal.Stop(sigHUP)

	// ── Blocklist Manager (Step 6) ────────────────────────────────────────────────────────
	// Создаётся до стримов, чтобы все детекторы разделяли один automata-граф.
	// Использует appCtx — refresh-горутины останавливаются на SIGTERM вместе со стримами.
	// Manager.Update() вызывается из SIGHUP fan-out ниже, а не per-stream.
	blMgr := blocklist.NewManager(ctx, cfg.Blocklist)
	defer blMgr.Close()

	// ── Chain Integrity Checker (Step 7) ──────────────────────────────────────────────
	// Детектирует Cloudflare или bogon IP в роли client IP в access-логах.
	// Должен стартовать до стримов — все записи лога проверяются с начала.
	// Оба поля — nil при chain_guard.enabled == false; вызывающие делают nil-check.
	var chainChecker *chaincheck.Checker
	var warningsWriter *output.WarningsWriter
	if cfg.ChainGuard.Enabled {
		var wErr error
		warningsWriter, wErr = output.NewWarningsWriter(cfg.ChainGuard.WarningsLog)
		if wErr != nil {
			utils.Log("STARTUP", "failed to open warnings log: "+wErr.Error(), "error")
			return
		}
		// warningsWriter deferred до chainChecker, чтобы LIFO закрыл writer последним —
		// любой in-flight WriteChainWarning завершится до закрытия файла.
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
				// Перечитываем операционный лог через свежий конфиг.
				newCfg, err := config.LoadConfig(path)
				if err == nil {
					if reloadErr := utils.Reload(newCfg.Logging.Debug, newCfg.Logging.ConsoleColor,
						newCfg.Output.OperationalLog, ""); reloadErr != nil {
						utils.Log("CONFIG", "SIGHUP: logger reload error: "+reloadErr.Error(), "warn")
					}
					// Обновляем blocklist Manager один раз для всех стримов — стримы
					// сами не вызывают Update, они перестраивают pipeline на базе
					// обновлённого shared automata.
					// Guard: если SIGTERM и SIGHUP приходят в одном select-тике,
					// ctx уже может быть отменён. Запускать новые горутины с отменённым
					// context безвредно, но бессмысленно — пропускаем update полностью.
					if ctx.Err() == nil {
						shared.BlocklistManager.Update(ctx, newCfg.Blocklist)
						// Обновляем chain checker новым конфигом (sources, intervals).
						// Тот же ctx.Err() guard: Update запускает горутину для CF refresh.
						if shared.ChainChecker != nil {
							shared.ChainChecker.Update(ctx, newCfg.ChainGuard.ToChainCheckConfig())
						}
					}
					// WarningsWriter.Reopen() безопасен после отмены ctx:
					// только закрывает/переоткрывает файл, никогда не запускает горутин.
					if shared.WarningsWriter != nil {
						_ = shared.WarningsWriter.Reopen()
					}
				}
				// Нотифицируем каждый стрим (неблокирующе: пропускаем, если канал
				// полон, что означает, что предыдущий reload ещё не обработан стримом).
				for _, ch := range reloadChs {
					select {
					case ch <- struct{}{}:
					default:
					}
				}
			}
		}
	}()

	// ── Pre-register Named Channel Switch queues с не-default backend'ами ─────────────
	// Pre-registration позволяет YAML'ному `queue: { type: bbolt, ... }` победить
	// позднейший вызов AttachWriter из sink'а (fan-in refcount++ на существующих именах).
	// Источники без `queue:` идут legacy-путём: sink создаёт собственную MemoryQueue
	// при первом AttachWriter. Ошибка — fatal: тихий откат на memory удивил бы
	// оператора после config-ошибки.
	if err := preRegisterExecutorQueues(&cfg); err != nil {
		utils.Log("STARTUP", "executor queue pre-registration: "+err.Error(), "error")
		os.Exit(1)
	}

	// ── Запуск executor-горутин (top-level автономные, Flow #042) ───────────────────────
	// Executors собираются из cfg.Executors и подключаются к Named Channel Switch sources,
	// регистрируемым sentinel-threat sink'ами внутри stream-pipeline (T5).
	// ── Запуск стримов (Flow 081 Phase 3: runtime.Run + securityFactory) ───────────────

	// MetricsCallbacks — адаптер из runtime-callback'ов в product metrics.* функции.
	// Engine зовёт:
	//   - RecordLine(s, p, src, st) на КАЖДОЙ строке ДО Process (даже при Skip) →
	//     здесь = RecordLine + RecordInputLine (как в старом processLine).
	//   - RecordOutputEvent(s, p, sinkName) — sinkType вычисляется из имени
	//     через sinkTypeFromName (как в старом processLine).
	//   - UpdateGauges — прямой проброс.
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

	// runtime.SharedResources — opaque контейнер, который engine пробрасывает
	// в factory.Build. Здесь мы кладём те же singleton'ы, что и в локальный
	// shared (нужен buildPipelineDetectors → bridgeShared).
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
	// SIGHUP-fanout: подменяем раннее-созданные reloadChs на те, что соответствуют
	// StreamSpec.Pipelines (те же индексы — main.go строит reloadChs в порядке cfg.Streams).
	reloadChs = streamReloadChs

	var wg sync.WaitGroup
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

	// Запускаем executors ПОСЛЕ stream-горутин, чтобы sentinel-threat sink'и успели
	// зарегистрировать свои Named Channel Switch каналы. Короткая задержка даёт
	// pipeline-горутинам дойти до runPipeline → buildSinks → AttachWriter до AttachReader.
	var execWg sync.WaitGroup
	if len(cfg.Executors) > 0 {
		go func() {
			time.Sleep(200 * time.Millisecond)
			if err := startExecutors(ctx, &cfg, &execWg); err != nil {
				utils.Log("STARTUP", "executor startup error: "+err.Error(), "error")
			}
		}()
	}

	// Уведомляем systemd, что все стримы запущены и сервис готов.
	// Status= отображается в выводе `systemctl status`.
	sdNotify("READY=1\nSTATUS=" + version + " running")

	metricsWg.Wait()
	wg.Wait()
	utils.Log("SHUTDOWN", "all streams done", "info")

	// ── Graceful executor shutdown ──────────────────────────────────────────────────
	// DetachWriter все NCS-источники, чтобы executor Run()-циклы вышли по закрытому каналу.
	for _, ec := range cfg.Executors {
		for _, src := range ec.Sources {
			ncs.DetachWriter(src.Name)
		}
	}
	execWg.Wait()
	utils.Log("SHUTDOWN", "all executors done", "info")
}
