// ========================== Entry point — arxsentinel ====================================
//   Инициализация компонентов, сборка pipeline, запуск демона.
//
//   ЧТО ЗДЕСЬ:
//     - main()                          — загрузка конфига, init логгера, metrics-сервер, запуск стримов
//     - runStream()                     — оркестратор стрима: строит TrackerGroup-карту, запускает runPipeline-горутины
//     - runPipeline()                   — изолированный processing-юнит: sources, detectors, sinks, whitelist, scorer
//     - buildPipelineDetectors()        — собирает список детекторов из registry (pkg/detector)
//     - buildSources() / buildSinks()   — построение списка плагинов из pipeline-конфига
//     - buildParserForInput()           — выбор парсера по profile/input-конфигурации
//     - startExecutors()                — top-level автономные горутины (NCS-based, Flow #042)
//     - processLine()                   — ядро pipeline: whitelist → tracking → scoring → sinks
//     - sdNotify()                      — systemd readiness-нотификация
//     - metricsHandler()                — Prometheus metrics-endpoint с опциональной bcrypt-авторизацией
//     - activeEnvOverrides()            — диагностика: логирует активные ARXSENTINEL_* переменные
//     - writePID() / removePID()        — управление PID-файлом демона
//
//   ЧЕГО ЗДЕСЬ НЕТ:
//     - Бизнес-логика (core/)
//     - Структуры конфигурации (sys/config)
//     - Логирование (sys/utils)
//     - Подкоманда cleanup (cleanup.go)
//     - Подкоманда validate (validate.go)
//     - Подкоманда license (license.go)
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
//   Multi-stream: каждый стрим работает в своём наборе горутин (runStream).
//   Backward compat: general.log_file → один безымянный стрим, метка stream="" в метриках.
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
//     3. runStream returns → wg.Done()  — стрим полностью завершён
//     4. metricsWg.Wait()               — HTTP-сервер Shutdown() завершён (таймаут 5s)
//     5. wg.Wait() in main()            — все стримы подтверждённо завершены
//     6. defers LIFO: cancel() → removePID() → utils.Close()
//
//   ИНВАРИАНТЫ:
//     - Ни одна горутина не стартует с context.Background() — все используют appCtx или derived
//     - Каждая горутина, удерживающая ресурсы, трекается в WaitGroup
//     - SIGHUP никогда не гонится с обработкой строк — оба в одной select-горутине на стрим

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
	_ "github.com/mr-addams/arxsentinel/pkg/executor/mikrotik"
	_ "github.com/mr-addams/arxsentinel/pkg/executor/nginx"
	"github.com/mr-addams/arxsentinel/pkg/plugin"
	_ "github.com/mr-addams/arxsentinel/pkg/processor"
	pkgsink "github.com/mr-addams/arxsentinel/pkg/sink"
	_ "github.com/mr-addams/arxsentinel/pkg/sink/exec"
	pkgsinkfile "github.com/mr-addams/arxsentinel/pkg/sink/file"
	_ "github.com/mr-addams/arxsentinel/pkg/sink/sentinel"
	_ "github.com/mr-addams/arxsentinel/pkg/sink/stdout"
	pkgsource "github.com/mr-addams/arxsentinel/pkg/source"
	_ "github.com/mr-addams/arxsentinel/pkg/source/exec"
	_ "github.com/mr-addams/arxsentinel/pkg/source/file"
	_ "github.com/mr-addams/arxsentinel/pkg/source/http"
	_ "github.com/mr-addams/arxsentinel/pkg/source/sentinel"
	_ "github.com/mr-addams/arxsentinel/pkg/source/stdin"
	_ "github.com/mr-addams/arxsentinel/pkg/source/syslog"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// version инжектируется goreleaser через ldflags (-X main.version={{.Version}}).
// Остаётся "dev" при ручной сборке без ldflags.
var version = "dev"

// PipelineContext хранит долгоживущие зависимости, разделяемые processLine.
// Пересоздаётся при SIGHUP-reload: Scorer и Matcher заменяются; Tracker и Verifier переживают reload.
// Sinks переживают reload — FileSink.Reload() обрабатывает ротацию логов на месте.
// FakeBotScore и DNSVerifyTimeout отражают текущий конфиг.
// Shared передаётся по значению — поля SharedResources это указатели, поэтому копия
// дешёвая, и любой nil-check в processLine корректно отражает состояние на момент
// построения pipeline.
type PipelineContext struct {
	StreamName       string              // YAML: streams[].name, "" — stream identifier for metrics/logs. Consumer: metrics, processLine
	PipelineName     string              // YAML: pipelines[].name, "" — pipeline identifier. Consumer: metrics
	processedCount   *atomic.Int64       // Internal — per-pipeline counter, owned by runPipeline. Consumer: stats goroutine
	threatCount      *atomic.Int64       // Internal — per-pipeline threat counter, owned by runPipeline. Consumer: stats goroutine
	Tracker          *state.Tracker      // YAML: state.tracker_gc_interval, 5m — IP state storage. Consumer: processLine (line 1200)
	Scorer           *scorer.Scorer      // Internal — scoring engine built from detectors. Consumer: processLine (line 1220)
	Sinks            []plugin.Sink       // YAML: streams[].outputs — threat output destinations. Consumer: processLine (line 1248)
	Executors        []plugin.Executor   // YAML: executors[].name — NCS source consumers. Consumer: N/A (top-level, not used by processLine)
	Matcher          *whitelist.Matcher  // YAML: whitelist.ip_whitelist, cidr_whitelist, ua_whitelist, path_whitelist — early-exit rules. Consumer: processLine
	Verifier         *whitelist.Verifier // Internal — rDNS/fDNS bot verification. Consumer: processLine (line 1178)
	FakeBotScore     int                 // YAML: whitelist.fake_bot_score, 50 — penalty applied before scoring. Consumer: processLine (line 1213)
	DNSVerifyTimeout time.Duration       // YAML: whitelist.dns_verify_timeout, 2s — per-request DNS timeout. Consumer: processLine (line 1177)
	Shared           SharedResources     // Internal — chain checker + warnings writer (nil when disabled). Consumer: processLine (line 1152)
	SourceName       string              // Internal — ThreatEvent metadata, warnings file. Consumer: ThreatEvent, WarningsWriter
	SourceType       string              // Internal — ThreatEvent metadata ("file"|"stdin"). Consumer: ThreatEvent, metrics
}

// SharedResources хранит singleton-зависимости, общие для всех стримов.
// Создаётся один раз в main() до запуска стримов; передаётся в buildDetectors.
// Manager.Update() вызывается при SIGHUP из fan-out-горутины — per-stream
// SIGHUP-хендлеры перестраивают только pipeline, не общий blocklist-state.
// ChainChecker и WarningsWriter — nil при chain_guard.enabled == false —
// все вызывающие обязаны делать nil-check перед использованием.
type SharedResources struct {
	BlocklistManager *blocklist.Manager
	ChainChecker     *chaincheck.Checker    // nil if chain_guard disabled
	WarningsWriter   *output.WarningsWriter // nil if chain_guard disabled
}

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
	// ── Запуск стримов ────────────────────────────────────────────────────────────────

	var wg sync.WaitGroup
	for i, streamCfg := range cfg.Streams {
		wg.Add(1)
		go runStream(ctx, path, cfg, streamCfg, ipCache, resolver, reloadChs[i], &wg, shared)
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
			pkgexecutor.DetachWriter(src.Name)
		}
	}
	execWg.Wait()
	utils.Log("SHUTDOWN", "all executors done", "info")
}

// runStream — оркестратор одного стрима.
// Вызывается из: main (строка 454).
// Неблокирующий.
//
// Строит TrackerGroup-карту, запускает GC-горутины для каждого shared-tracker'а,
// затем запускает по одной runPipeline()-горутине на pipeline. Возвращается,
// когда все pipeline'ы вышли.
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
	// Восстанавливаемся после panic — один упавший стрим не должен уронить остальные.
	defer func() {
		if r := recover(); r != nil {
			utils.Log("ERROR", fmt.Sprintf("stream %q: panic recovered: %v", streamCfg.Name, r), "error")
		}
	}()

	// Строим TrackerGroup-карту — pipeline'ы с одинаковой группой разделяют один
	// *state.Tracker. Auto-wrapped legacy-pipeline'ы (Name="", TrackerGroup="")
	// все попадают в группу "" и разделяют один tracker, что соответствует
	// поведению до Task 3.
	trackers := buildTrackerGroups(cfg, streamCfg)

	// Запускаем по одной GC-горутине на уникальный tracker.
	// Два pipeline'а в одной группе разделяют tracker — запуск двух GC-горутин
	// на одном tracker'е удвоил бы частоту GC, что некорректно.
	for _, tracker := range trackers {
		go tracker.RunGC(ctx, time.Duration(cfg.State.GCInterval))
	}

	// Запускаем по одной горутине на каждый PipelineConfig.
	var pipelineWg sync.WaitGroup
	for i, pipeCfg := range streamCfg.Pipelines {
		pipelineWg.Add(1)
		tracker := trackers[resolveTrackerGroup(pipeCfg)]
		go runPipeline(ctx, path, cfg, streamCfg, pipeCfg, i, tracker, ipCache, resolver, reloadCh, &pipelineWg, shared)
	}
	pipelineWg.Wait()
}

// runPipeline запускает один изолированный pipeline внутри стрима.
// Вызывается из: runStream (строка 528).
// Неблокирующий.
//
// Владеет своими Sources, Sinks, Whitelist Matcher/Verifier и Scorer.
// Разделяет Tracker из trackers[resolveTrackerGroup(pipeCfg)] с соседними pipeline'ами
// с тем же tracker_group.
//
// Переживает SIGHUP: перечитывает конфиг, перестраивает Scorer+Matcher, вызывает
// FileSink.Reload(). Sources НЕ перезапускаются на SIGHUP — они работают
// непрерывно через reload'ы.
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

	// Per-pipeline счётчики.
	var processedCount atomic.Int64
	var threatCount atomic.Int64

	logTag := pipelineLogTag(streamCfg.Name, pipeCfg.Name)

	// Per-pipeline whitelist matcher (IP/CIDR/UA-правила).
	matcher, err := whitelist.NewMatcher(cfg.Whitelist)
	if err != nil {
		utils.Log("ERROR", fmt.Sprintf("%s: whitelist init error: %v", logTag, err), "error")
		return
	}

	// Verifier использует shared ipCache — DNS-результаты не специфичны для pipeline.
	verifier := whitelist.NewVerifier(ipCache, resolver, utils.Log)

	// Строим sources и sinks из конфига pipeline.
	sources, err := buildSources(cfg, pipeCfg.Inputs)
	if err != nil {
		utils.Log("ERROR", fmt.Sprintf("%s: source init error: %v", logTag, err), "error")
		return
	}
	sinks, err := buildSinks(ctx, pipeCfg.Outputs)
	if err != nil {
		utils.Log("ERROR", fmt.Sprintf("%s: sink init error: %v", logTag, err), "error")
		return
	}
	defer func() {
		for _, sink := range sinks {
			_ = sink.Close()
		}
	}()

	// Executors — top-level автономные горутины (Flow #042), стартующие из main().
	// Pipeline больше не владеет executor'ами — они читают из Named Channel Switch (NCS).
	var executors []plugin.Executor
	sourceName, sourceType := sourceMetadata(sources)

	// Выбираем размер буфера: override на уровне pipeline или дефолт стрима.
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

	// Stats-горутина — периодическая строка операционного лога.
	// Захватывает processedCount, threatCount, tracker, tag напрямую —
	// не обращается к переменной pipe, которая может быть переприсвоена на SIGHUP.
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

	// Fan-in всех sources в один entries-канал.
	// Sources работают в горутинах, запускаемых Merge, и останавливаются при отмене ctx.
	entries := coreinput.Merge(ctx, sources, bufSize, utils.Log)

	utils.Log("STARTUP", fmt.Sprintf(
		"%s: pipeline started (sources=%d sinks=%d) | source: %s",
		logTag, len(sources), len(sinks), sourceName,
	), "info")

	// ── Главный processing-цикл ──────────────────────────────────────────────────────

	for {
		select {
		case <-ctx.Done():
			utils.Log("SHUTDOWN", fmt.Sprintf("%s: signal received, draining buffer...", logTag), "info")
			// Sources останавливаются на ctx.Done(), и Merge закрывает entries, когда
			// все sources вышли. context.Background() вместо ctx: ctx уже отменён, иначе
			// verifyCtx (context.WithTimeout(ctx,...)) был бы сразу отменён → все боты
			// получили бы isFakeBot=true → ложные ban-записи в threats.log на shutdown.
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
			// Ищем обновлённый stream-конфиг по имени; откатываемся на текущий, если удалён.
			newStreamCfg := streamCfg
			for _, s := range newCfg.Streams {
				if s.Name == streamCfg.Name {
					newStreamCfg = s
					break
				}
			}
			newPipeCfg := findPipelineCfg(newStreamCfg, pipeCfg.Name, pipeIdx, pipeCfg)
			// Reload FileSinks для ротации логов.
			// Sources НЕ перезапускаются — они работают непрерывно через reload'ы.
			for _, sink := range pipe.Sinks {
				if fs, ok := sink.(*pkgsinkfile.FileSink); ok {
					if reloadErr := fs.Reload(); reloadErr != nil {
						utils.Log("CONFIG", fmt.Sprintf("%s: SIGHUP sink reload error: %v", logTag, reloadErr), "warn")
					}
				}
			}
			// Executors — top-level автономные горутины (Flow #042) — здесь не перестраиваются на SIGHUP.
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
				Sinks:            sinks,     // те же sinks — уже перезагружены выше
				Executors:        executors, // те же executors — state (ban list, TTL) должен пережить reload
				Matcher:          newMatcher,
				Verifier:         verifier,
				FakeBotScore:     cfg.Whitelist.FakeBotScore,
				DNSVerifyTimeout: time.Duration(cfg.Whitelist.DNSVerifyTimeout),
				Shared:           shared,
				SourceName:       sourceName, // идентичность source не меняется на SIGHUP
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
// Called from: runStream (line 514).
// Non-blocking.
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
// Called from: runStream (line 527), buildTrackerGroups (line 737).
// Non-blocking.
//
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
// Called from: runPipeline (lines 561, 664, 668, 674, 716, 720), main (lines 280, 285).
// Non-blocking.
//
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
// Called from: runPipeline (line 684).
// Non-blocking.
//
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
// Called from: bridgeShared (line 804).
// Non-blocking.
//
// *blocklist.Manager satisfies pkgdetector.Matcher implicitly (has Match(list, text) bool).
type detectorShared struct {
	blocklist pkgdetector.Matcher
}

// Blocklist implements pkgdetector.SharedResources. Called from: bridgeShared (line 804).
// Non-blocking.
func (s detectorShared) Blocklist() pkgdetector.Matcher { return s.blocklist }

// bridgeShared wraps SharedResources into the pkgdetector.SharedResources interface.
// Called from: buildPipelineDetectors (line 816).
// Non-blocking.
//
// Returns nil when shared.BlocklistManager is nil so detector factories (badbot) get
// a nil SharedResources and fall back to noopMatcher instead of a non-nil interface
// wrapping a nil *blocklist.Manager (which would panic on MatchResult).
func bridgeShared(shared SharedResources) pkgdetector.SharedResources {
	if shared.BlocklistManager == nil {
		return nil
	}
	return detectorShared{blocklist: shared.BlocklistManager}
}

// buildPipelineDetectors constructs the detector list for a pipeline.
// Called from: runPipeline (lines 607, 705).
// Non-blocking.
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
				Exec:    dc.Exec, // exec plugin binary path (empty for built-in detectors)
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
// Called from: buildPipelineDetectors (line 821).
// Non-blocking.
//
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
// Called from: buildSources (line 940).
// Non-blocking.
//
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
// Called from: runPipeline (line 574).
// Non-blocking.
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
			Type:          in.Type,
			Path:          in.Path,
			Exec:          in.Exec, // NEW
			Addr:          in.Addr,
			Mode:          in.Mode,
			URL:           in.URL,
			HTTPPath:      in.HTTPPath,
			Token:         in.Token,
			TLSCert:       in.TLSCert,
			TLSKey:        in.TLSKey,
			Protocol:      in.Protocol,
			EnvelopeField: in.EnvelopeField,
			PullInterval:  in.PullInterval,
			MaxBodyBytes:  in.MaxBodyBytes,
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

// preRegisterExecutorQueues pre-registers each executor source that has a queue:
// section with its declared backend (bbolt/redis) and verifies that every
// pre-registered name is referenced by at least one sentinel-threat output in
// the pipeline.
//
// Without the wiring check, a typo in an executor source name silently creates
// a pre-registered backend queue (never written to) while the sink creates a
// fresh MemoryQueue on first AttachWriter. Events then flow into memory
// instead of the intended bbolt/redis backend, with no error surfaced. This
// function returns a fail-fast error in that case.
//
// Sources without queue: are skipped (legacy MemoryQueue path inside the sink
// cannot drift from the executor's source list).
//
// Other failure modes also return errors: bbolt file open failure, unreachable
// Redis, unknown queue type. All are configuration errors that should abort
// startup rather than silently degrade.
//
// IMPORTANT: validation runs FIRST and must complete cleanly across the whole
// config before any RegisterSinkFromConfig call touches the Named Channel
// Switch. Otherwise a partial registration (one source OK, the next missing
// its sink) would leave an orphan bbolt/redis queue sitting in hubQueues with
// no way to clean it up — the operator would have to restart the process to
// free it.
func preRegisterExecutorQueues(cfg *config.Config) error {
	available := collectSentinelSinkNames(cfg)

	// Phase 1: wiring check. Read-only — no side effects on the channel switch.
	for _, ec := range cfg.Executors {
		for _, src := range ec.Sources {
			if src.Queue == nil {
				continue
			}
			if _, ok := available[src.Name]; !ok {
				return fmt.Errorf(
					"executor %q source %q (queue=%s) is not referenced by any sentinel-threat output; "+
						"available sink names: [%s]",
					ec.Name, src.Name, src.Queue.Type, strings.Join(sortedKeys(available), ", "),
				)
			}
		}
	}

	// Phase 2: registration. Only reached when every queue: section matches an
	// existing sentinel-threat output, so hubQueues is consistent post-call.
	for _, ec := range cfg.Executors {
		for _, src := range ec.Sources {
			if src.Queue == nil {
				continue
			}
			if err := pkgexecutor.RegisterSinkFromConfig(src.Name, src.Queue); err != nil {
				return fmt.Errorf("executor %q source %q: %w", ec.Name, src.Name, err)
			}
		}
	}
	return nil
}

// collectSentinelSinkNames returns the set of channel names declared by
// sentinel-threat outputs in any of the three config locations (top-level,
// per-stream, per-pipeline). Non-sentinel-threat outputs and empty names are
// ignored — the sentinel sink rejects empty names at construction time.
func collectSentinelSinkNames(cfg *config.Config) map[string]struct{} {
	set := make(map[string]struct{})
	add := func(outputs []config.SinkConfig) {
		for _, out := range outputs {
			if out.Type != "sentinel-threat" || out.Name == "" {
				continue
			}
			set[out.Name] = struct{}{}
		}
	}
	add(cfg.Outputs)
	for _, s := range cfg.Streams {
		add(s.Outputs)
		for _, p := range s.Pipelines {
			add(p.Outputs)
		}
	}
	return set
}

// sortedKeys returns the keys of m in deterministic order. Used for stable
// error messages.
func sortedKeys(m map[string]struct{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// startExecutors builds all top-level executors from config and launches them as goroutines.
// Called from: main (line 464).
// Non-blocking.
//
// Each executor connects to Named Channel Switch sources and runs until ctx is cancelled
// or the source channel is closed. Must be called after all NCS sinks are registered.
//
// Returns an error if any executor cannot be built or any named source cannot be found.
// On error, the caller should log and continue — executor startup failure is not fatal
// for the rest of the pipeline (streams still process logs).
func startExecutors(ctx context.Context, cfg *config.Config, wg *sync.WaitGroup) error {
	for _, ec := range cfg.Executors {
		ex, err := pkgexecutor.Build(pkgexecutor.ExecutorConfig{
			Name:   ec.Name,
			Type:   ec.Type,
			Config: ec.Config,
		})
		if err != nil {
			return fmt.Errorf("executor %q: build: %w", ec.Name, err)
		}

		for _, src := range ec.Sources {
			q, err := pkgexecutor.AttachReader(src.Name)
			if err != nil {
				return fmt.Errorf("executor %q: source %q: %w", ec.Name, src.Name, err)
			}

			wg.Add(1)
			go func(ex plugin.Executor, q plugin.EventSource) {
				defer wg.Done()
				if err := ex.Run(ctx, q); err != nil && err != context.Canceled {
					utils.Log("EXECUTOR", fmt.Sprintf("executor %s: %v", ex.Name(), err), "error")
				}
			}(ex, q)
		}
	}
	return nil
}

// buildSinks constructs the Sink list from an explicit outputs slice.
// Called from: runPipeline (line 579).
// Non-blocking.
func buildSinks(ctx context.Context, outputs []config.SinkConfig) ([]plugin.Sink, error) {
	if len(outputs) == 0 {
		return nil, fmt.Errorf("no outputs configured")
	}
	sinks := make([]plugin.Sink, 0, len(outputs))
	for _, out := range outputs {
		sink, err := pkgsink.Build(ctx, pkgsink.SinkConfig{
			Type:   out.Type,
			Name:   out.Name,
			Path:   out.Path,
			Format: out.Format,
			Exec:   out.Exec,
		})
		if err != nil {
			return nil, fmt.Errorf("sink %q: %w", out.Type, err)
		}
		sinks = append(sinks, sink)
	}
	return sinks, nil
}

// sourceMetadata returns the name and type of the first source for ThreatEvent metadata.
// Called from: runPipeline (line 593).
// Non-blocking.
//
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
// Called from: processLine (line 1253).
// Non-blocking.
//
// "file:/path/…" → "file", "stdout" → "stdout".
func sinkTypeFromName(name string) string {
	if strings.HasPrefix(name, "file:") {
		return "file"
	}
	return name
}

// streamSourceLabel returns a short human-readable source description for startup logging.
// Called from: main (lines 280, 285).
// Non-blocking.
//
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
// Called from: main (line 230).
// Non-blocking.
func parseFlagInputs(flagVal string, cfg config.Config) []config.InputConfig {
	switch flagVal {
	case "stdin":
		return []config.InputConfig{{Type: "stdin", Parser: cfg.Parser.LogFormat}}
	default:
		return []config.InputConfig{{Type: "file", Path: flagVal, Parser: cfg.Parser.LogFormat}}
	}
}

// parseFlagOutputs converts the --output flag value into a SinkConfig slice.
// Called from: main (line 234).
// Non-blocking.
//
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
// Called from: main (line 263).
// Non-blocking.
//
// Used for: kill -HUP $(cat pid) and logrotate postrotate (Task 7.1).
// On error — the caller logs a warn and continues: PID is not critical.
func writePID(path string) error {
	return os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())+"\n"), 0644)
}

// removePID removes the PID file when the daemon exits.
// Called from: main (line 266) via defer.
// Non-blocking.
//
// Called via defer — fires on any return from main, including SIGTERM.
// Error on removal is intentionally ignored: the file may have been deleted manually by an operator.
func removePID(path string) {
	_ = os.Remove(path)
}

// processLine processes a single parsed log entry: whitelist early-exit → tracking → fake bot penalty → scoring → sinks.
// Called from: runPipeline (lines 660, 723).
// Non-blocking.
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

	// Forwarder mode (Flow #041) removed: Flow #042 replaces with NCS-based dispatch (T5/T10).

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
	if pipe.Matcher.IsWhitelistedIP(entry.RealIP) || pipe.Matcher.IsWhitelistedUA(entry.UserAgent) || pipe.Matcher.IsWhitelistedPath(entry.Path) {
		utils.Log("WHITELIST", "skipping via custom whitelist: "+entry.RealIP, "debug")
		return
	}

	// ── Steps 2–3: bot detection and verification ────────────────────────────────────
	// MatchBot is fast (strings.Contains over slice). Verify caches the result —
	// DNS request is only made on the first occurrence of a new IP with a bot UA.
	// verifyCtx with timeout: limits pipeline blocking (see KNOWN LIMITATION above).
	isFakeBot := false
	var exemptSet map[string]struct{}
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

		// UA-only bot (no rDNS, no IP ranges): verified=false, isFakeBot=false.
		// Build exemptSet from botCfg.ExemptDetectors so certain detectors are skipped.
		if !verified && !isFakeBot && matched && len(botCfg.ExemptDetectors) > 0 {
			exemptSet = make(map[string]struct{}, len(botCfg.ExemptDetectors))
			for _, name := range botCfg.ExemptDetectors {
				exemptSet[name] = struct{}{}
			}
			utils.Log("WHITELIST", fmt.Sprintf("ua_only bot %s: exempt detectors %v", entry.RealIP, botCfg.ExemptDetectors), "debug")
		}
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
	level, score, modules, reason := pipe.Scorer.Evaluate(ipState, entry, exemptSet)

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
		// Передаём ctx процесса в sink, чтобы in-flight записи
		// (особенно сетевые Push в Sentinel Hub) могли быть отменены при shutdown.
		if err := sink.Write(ctx, event); err != nil {
			utils.Log("ERROR", fmt.Sprintf("stream %q: sink %s: %v", pipe.StreamName, sink.Name(), err), "error")
			continue
		}
		metrics.RecordOutputEvent(pipe.StreamName, pipe.PipelineName, sink.Name(), sinkTypeFromName(sink.Name()))
	}

	// Executor dispatch removed: Flow #042 executors are autonomous goroutines
	// reading from Named Channel Switch (NCS). Wired in T4b/T5.
}

// ========================== systemd notify ===============================================

// sdNotify sends a state notification to systemd via NOTIFY_SOCKET.
// Called from: main (line 472).
// Non-blocking.
//
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
// Called from: main (line 324).
// Non-blocking.
//
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
// Called from: main (line 291).
// Non-blocking.
//
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
