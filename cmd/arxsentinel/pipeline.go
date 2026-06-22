// ========================== Pipeline — stream orchestration ===========================
//   Изолированный processing-юнит: sources → detectors → sinks.
//   runStream оркестрирует стрим, runPipeline запускает pipeline,
//   processLine — ядро обработки одной строки.
//
//   ЧТО ЗДЕСЬ:
//     - PipelineContext          — контекст pipeline: tracker, scorer, sinks, matcher
//     - SharedResources          — общие ресурсы: blocklist, chain checker, warnings writer
//     - runStream()              — оркестратор стрима: трекеры, goroutine per pipeline
//     - runPipeline()            — isolated processing unit: sources → detectors → sinks
//     - processLine()            — ядро: whitelist → tracking → scoring → sinks
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

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mr-addams/arxsentinel/internal/core/blocklist"
	"github.com/mr-addams/arxsentinel/internal/core/chaincheck"
	coreinput "github.com/mr-addams/arxsentinel/internal/core/input"
	"github.com/mr-addams/arxsentinel/internal/core/output"
	"github.com/mr-addams/arxsentinel/internal/core/scorer"
	"github.com/mr-addams/arxsentinel/internal/core/state"
	"github.com/mr-addams/arxsentinel/internal/core/whitelist"
	"github.com/mr-addams/arxsentinel/internal/sys/config"
	"github.com/mr-addams/arxsentinel/internal/sys/metrics"
	"github.com/mr-addams/arxsentinel/internal/sys/utils"
	"github.com/mr-addams/arx-core/pkg/plugin"
	pkgsinkfile "github.com/mr-addams/arxsentinel/pkg/sink/file"
)

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
		Scorer:           scorer.NewScorer(cfg.Scoring, buildPipelineDetectors(ctx, cfg, pipeCfg, shared), utils.Log),
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
				Scorer:           scorer.NewScorer(cfg.Scoring, buildPipelineDetectors(ctx, cfg, pipeCfg, shared), utils.Log),
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
