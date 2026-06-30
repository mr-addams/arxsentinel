// ========================== Security factory — implements LineProcessorFactory =============
//   Этот файл — реализация runtime.LineProcessorFactory на стороне Product.
//
//   ЧТО ЗДЕСЬ:
//     - securityFactory      — фабрика per-pipeline state; реализует оба интерфейса
//                              (LineProcessorFactory + LineProcessor — это намеренно,
//                              engine.Run делает type-assert).
//     - Build()              — построение matcher / verifier / scorer / tracker;
//                              старт GC-горутины один раз на группу tracker'а.
//     - Reload()             — SIGHUP-reload: перечитывает config, перестраивает
//                              matcher + scorer + detectors; tracker reuse.
//
//   КРИТИЧЕСКИ ВАЖНО: Build/Reload содержат побочные эффекты (старт GC, чтение
//   файлов). Не модифицировать без пересмотра DECISIONS.md Flow 081.
//
//   ОДИН factory на стрим: main.go создаёт один экземпляр securityFactory на
//   каждый cfg.Streams[i], передаёт в runtime.Run (engine делает type-assert
//   на LineProcessor — фабрика должна реализовывать оба интерфейса).
//
//   СВЯЗЬ С DECISIONS.md:
//     - TrackerGroup: Pipeline.TrackerGroup → resolveTrackerGroup; shared внутри
//       фабрики через trackers map[string]*state.Tracker (mutex guarded).
//     - GC: один раз на tracker (а не на pipeline) — оригинальная семантика,
//       см. securityFactory.getOrCreateTracker.
//     - Sources/Sinks НЕ строятся здесь — это делает runtime_adapter.go и
//       передаёт в engine через StreamSpec.Pipelines[i].Sinks/Sources.

package main

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/mr-addams/arxsentinel/internal/core/blocklist"
	"github.com/mr-addams/arxsentinel/internal/core/scorer"
	"github.com/mr-addams/arxsentinel/internal/core/state"
	"github.com/mr-addams/arxsentinel/internal/core/whitelist"
	"github.com/mr-addams/arxsentinel/internal/sys/config"
	"github.com/mr-addams/arxsentinel/internal/sys/utils"
	coreruntime "github.com/mr-addams/arx-core/pkg/runtime"
	"github.com/mr-addams/arx-core/pkg/plugin"
	"github.com/mr-addams/arxsentinel/pkg/processorplugins/waf"
	"gopkg.in/yaml.v3"
)

// ++++++++++++++++++++++++++ securityFactory — Product-side factory ++++++++++++++++++++++++

// securityFactory реализует runtime.LineProcessorFactory + runtime.LineProcessor.
//
// Один factory-экземпляр на стрим. main.go создаёт его ДО runtime.Run,
// передаёт engine как `factory`. Engine делает type-assert:
//   - LineProcessorFactory — для Build/Reload;
//   - LineProcessor        — для Process (вызов factory.Process делегирует
//     securityProcessor-инстансу с shared).
//
// shared — runtime.SharedResources (opaque). Security-домен поля (ChainChecker
// / WarningsWriter / BlocklistManager) доступны через type-assert.
type securityFactory struct {
	ctx      context.Context // app context — для tracker.RunGC
	path     string          // путь к config.yaml — для Reload
	ipCache  *whitelist.IPCache
	resolver *net.Resolver

	cfg   config.Config // snapshot на момент создания фабрики; Reload обновляет
	cfgMu sync.Mutex    // guard для cfg между Reload (несколько pipeline'ов перечитывают)

	streamName    string
	streamNameIdx int

	// Per-stream cache tracker'ов по группе. Один и тот же *state.Tracker
	// разделяется между pipeline'ами одной группы — оригинальная семантика
	// (pipeline.go:139-146 buildTrackerGroups).
	trackers  map[string]*state.Tracker
	trackerMu sync.Mutex

	// shared — immutable после создания (мы только читаем). Копируется
	// в securityProcessor.Process через &securityProcessor{shared: f.shared}.
	shared coreruntime.SharedResources
}

// Compile-time гарантии: factory удовлетворяет ОБА интерфейса runtime.
var (
	_ coreruntime.LineProcessorFactory = (*securityFactory)(nil)
	_ coreruntime.LineProcessor        = (*securityFactory)(nil)
)

// ── Process — делегирует securityProcessor.Process ++++++++++++++++++++++++++++++++++++++++

// Process — entry point для engine.dispatchEntry. Создаёт securityProcessor
// (с shared) на лету и делегирует ему обработку.
//
// На каждом вызове создаётся НОВЫЙ securityProcessor — дешёвая аллокация
// (1 поле shared pointer); GC-давления не создаёт (escape analysis inlines).
func (f *securityFactory) Process(
	ctx context.Context,
	event *plugin.Event,
	ps coreruntime.ProcessorState,
	evctx coreruntime.EventContext,
) coreruntime.Action {
	return (&securityProcessor{shared: f.shared}).Process(ctx, event, ps, evctx)
}

// ── Build — построить per-pipeline ProcessorState ++++++++++++++++++++++++++++++++++++++++

// Build — построить per-pipeline ProcessorState.
// Вызывается arx-core/pkg/runtime engine.runPipeline ОДИН раз на старте pipeline.
// Внутри:
//  1. Резолвим pipeCfg по stream/pipe/idx (snapshot cfg под cfgMu).
//  2. Matcher, Verifier, Scorer + detectors (через buildPipelineDetectors).
//  3. Tracker: shared per-group; создаём под trackerMu если ещё нет.
//  4. Стартуем GC-горутину ОДИН раз на уникальный tracker (ctx = f.ctx).
func (f *securityFactory) Build(
	streamName, pipeName string,
	pipeIdx int,
	shared coreruntime.SharedResources,
) (coreruntime.ProcessorState, error) {
	f.cfgMu.Lock()
	cfg := f.cfg
	f.cfgMu.Unlock()

	// Резолвим stream/pipe конфиги. Для Build нет старого state — fallback на
	// pipeName/idx из входных параметров; в норме cfg.Streams содержит нужный стрим.
	streamCfg, ok := findStreamCfg(cfg, streamName)
	if !ok {
		return nil, fmt.Errorf("stream %q not found in config", streamName)
	}
	pipeCfg := findPipelineCfg(streamCfg, pipeName, pipeIdx, streamCfg.Pipelines[pipeIdx])

	// Matcher — может упасть на ошибке конфига.
	matcher, err := whitelist.NewMatcher(cfg.Whitelist)
	if err != nil {
		return nil, fmt.Errorf("whitelist init error: %w", err)
	}

	// Verifier использует общий IPCache (DNS-результаты не специфичны для pipeline).
	verifier := whitelist.NewVerifier(f.ipCache, f.resolver, utils.Log)

	// bridgeShared требует старый cmd/arxsentinel SharedResources (используется
	// в buildPipelineDetectors). Конвертируем runtime.SharedResources → old.
	oldShared := bridgeRuntimeShared(shared)
	detectors := buildPipelineDetectors(f.ctx, cfg, pipeCfg, oldShared)
	scorerRef := scorer.NewScorer(cfg.Scoring, detectors, utils.Log)

	// Tracker — shared per-group. Один и тот же *state.Tracker между pipeline'ами
	// одной группы (DECISIONS.md Flow 081, оригинальная семантика buildTrackerGroups).
	group := resolveTrackerGroup(pipeCfg)
	tracker := f.getOrCreateTracker(group, cfg)

	// WAF processor — optional, nil-safe. Built from the first `plugin: waf`
	// entry in pipeCfg.Processors; empty list → Waf=nil, WAF gate is a no-op.
	// ScoreFn closure binds the per-group tracker so WAF can signal score
	// deltas directly into the same IPState securityProcessor consults later.
	wafProc, err := buildWafProcessor(pipeCfg.Processors, tracker, cfg.Scoring.BanThreshold)
	if err != nil {
		return nil, fmt.Errorf("waf init error: %w", err)
	}

	return &securityState{
		StreamName:       streamName,
		PipelineName:     pipeName,
		PipelineIdx:      pipeIdx,
		Tracker:          tracker,
		Scorer:           scorerRef,
		Matcher:          matcher,
		Verifier:         verifier,
		Waf:              wafProc,
		FakeBotScore:     cfg.Whitelist.FakeBotScore,
		DNSVerifyTimeout: time.Duration(cfg.Whitelist.DNSVerifyTimeout),
	}, nil
}

// ── Reload — SIGHUP-equivalent reload +++++++++++++++++++++++++++++++++++++++++++++++++++++

// Reload — SIGHUP-equivalent reload. Возвращает НОВЫЙ *securityState; engine
// атомарно подменяет. Tracker и Verifier переживают reload (общий по группе;
// их state (ban list, DNS cache) должен пережить reload).
//
// Шаги аналогичны исходному reload-блоку в runPipeline, перенесённому в
// arx-core/pkg/runtime (engine.runPipeline, case <-reloadCh).
func (f *securityFactory) Reload(
	old coreruntime.ProcessorState,
	ctx context.Context,
) (coreruntime.ProcessorState, error) {
	oldState, ok := old.(*securityState)
	if !ok {
		return nil, fmt.Errorf("Reload: unexpected state type %T", old)
	}

	newCfg, err := config.LoadConfig(f.path)
	if err != nil {
		return nil, fmt.Errorf("SIGHUP reload error: %w", err)
	}

	newMatcher, err := whitelist.NewMatcher(newCfg.Whitelist)
	if err != nil {
		return nil, fmt.Errorf("SIGHUP whitelist error: %w", err)
	}

	// Ищем обновлённый stream-конфиг по имени; откатываемся на старый, если удалён.
	newStreamCfg, ok := findStreamCfg(newCfg, oldState.StreamName)
	if !ok {
		newStreamCfg = streamConfigFromOld(oldState)
	}
	newPipeCfg := findPipelineCfg(newStreamCfg, oldState.PipelineName, oldState.PipelineIdx,
		oldPipeConfigFromOld(oldState))

	// Обновляем snapshot cfg под мьютексом — следующие Build получат свежий cfg.
	f.cfgMu.Lock()
	f.cfg = newCfg
	f.cfgMu.Unlock()

	// detectors + Scorer — rebuild.
	oldShared := bridgeRuntimeShared(f.shared)
	detectors := buildPipelineDetectors(ctx, newCfg, newPipeCfg, oldShared)
	scorerRef := scorer.NewScorer(newCfg.Scoring, detectors, utils.Log)

	// Tracker.Reconfigure — внутри-состояние (windows, intervals) подстраивается
	// под новый конфиг, IPState-данные сохраняются.
	oldState.Tracker.Reconfigure(newCfg)

	// WAF — rebuild from new cfg (rules may have changed; RuleSet is read-only
	// compiled, so a fresh WafProcessor is required for new rules). Tracker
	// is reused → ScoreFn closure binds the same tracker (correct, same group).
	wafProc, err := buildWafProcessor(newPipeCfg.Processors, oldState.Tracker, newCfg.Scoring.BanThreshold)
	if err != nil {
		return nil, fmt.Errorf("waf reload error: %w", err)
	}

	utils.Log("CONFIG", fmt.Sprintf("%s: SIGHUP config reloaded",
		pipelineLogTag(oldState.StreamName, oldState.PipelineName)), "info")

	return &securityState{
		StreamName:       oldState.StreamName,
		PipelineName:     oldState.PipelineName,
		PipelineIdx:      oldState.PipelineIdx,
		Tracker:          oldState.Tracker,
		Scorer:           scorerRef,
		Matcher:          newMatcher,
		Verifier:         oldState.Verifier,
		Waf:              wafProc,
		FakeBotScore:     newCfg.Whitelist.FakeBotScore,
		DNSVerifyTimeout: time.Duration(newCfg.Whitelist.DNSVerifyTimeout),
	}, nil
}

// ── Helpers (private) ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

// getOrCreateTracker возвращает существующий tracker для группы или создаёт
// новый и стартует его GC-горутину ОДИН раз.
//
// trackerMu защищает map от concurrent first-time-creation в нескольких
// pipeline'ах одной группы (Run-старт гонка, если engine.Run запускает
// pipeline-горутины параллельно).
func (f *securityFactory) getOrCreateTracker(group string, cfg config.Config) *state.Tracker {
	f.trackerMu.Lock()
	defer f.trackerMu.Unlock()

	if t, ok := f.trackers[group]; ok {
		return t
	}
	t := state.NewTracker(cfg, utils.Log)
	f.trackers[group] = t
	// GC — ОДИН раз на tracker (DECISIONS.md Flow 081). f.ctx — appCtx,
	// отмена при SIGTERM/SIGINT останавливает GC.
	go t.RunGC(f.ctx, time.Duration(cfg.State.GCInterval))
	return t
}

// bridgeRuntimeShared конвертирует runtime.SharedResources в старый cmd/arxsentinel
// SharedResources для buildPipelineDetectors. Последний принимает старый тип через
// bridgeShared (builders.go) — Phase 4 унифицирует сигнатуру.
//
// Type-assert конкретного *blocklist.Manager здесь достаточен: bridgeShared
// (builders.go) использует ТОЛЬКО BlocklistManager, ChainChecker и WarningsWriter
// buildPipelineDetectors'у не нужны.
func bridgeRuntimeShared(shared coreruntime.SharedResources) SharedResources {
	out := SharedResources{}
	if mgr, ok := shared.BlocklistManager.(*blocklist.Manager); ok {
		out.BlocklistManager = mgr
	}
	return out
}

// findStreamCfg находит StreamConfig по имени. Используется для Reload (нет fallback).
func findStreamCfg(cfg config.Config, name string) (config.StreamConfig, bool) {
	for _, s := range cfg.Streams {
		if s.Name == name {
			return s, true
		}
	}
	return config.StreamConfig{}, false
}

// streamConfigFromOld восстанавливает минимальный StreamConfig из старого state —
// нужен когда новый cfg удалил стрим. findPipelineCfg при Reload использует
// fallback на старую pipeCfg (старый PipeConfig) — реальный pipeCfg в этом
// случае взять негде, поэтому fallback.
func streamConfigFromOld(old *securityState) config.StreamConfig {
	return config.StreamConfig{Name: old.StreamName}
}

// oldPipeConfigFromOld — заглушка для findPipelineCfg fallback. Используется только
// когда новый стрим не содержит нужный pipeline (sighup-remove). Минимальный
// stub — реальный pipeCfg в этом случае взять негде.
func oldPipeConfigFromOld(old *securityState) config.PipelineConfig {
	return config.PipelineConfig{Name: old.PipelineName}
}

// buildWafProcessor scans pipeCfg.Processors for the first entry with
// plugin=="waf" and returns a compiled *waf.WafProcessor, or nil if no WAF
// is configured. Shared by Build() and Reload() — the only difference between
// the two calls is the cfg.Processors slice and tracker reference.
//
// Implementation note: ProcessorConfig.Params is `map[string]any` after yaml
// parsing — yaml round-trip converts the `waf_config` sub-key into a typed
// waf.Config struct (yaml.v3 → waf.Config.Unmarshal). This is the same
// convention used elsewhere in arxsentinel for plugin-specific typed config
// (see DetectorConfig.Params round-trip in builders.go).
//
// ScoreFn is bound here so the closure captures the per-group *state.Tracker
// — WAF fires scoreFn(ip, delta) on drop / tag:<label> hits and the deltas
// land in the same IPState that securityProcessor's scorer reads later.
// banThreshold is used as DropScore fallback when the waf_config block does
// not set DropScore explicitly — keeps WAF ban-coordination in sync with
// cfg.Scoring.BanThreshold without operator duplication.
func buildWafProcessor(processors []config.ProcessorConfig, tracker *state.Tracker, banThreshold int) (*waf.WafProcessor, error) {
	for _, pc := range processors {
		if pc.Plugin != "waf" {
			continue
		}
		// `waf_config` may be absent (rules-only config with all knobs defaulted)
		// or typed (rebuilt config from a previous run).
		rawCfg, ok := pc.Params["waf_config"]
		if !ok {
			return nil, fmt.Errorf("waf: plugin entry missing required key %q", "waf_config")
		}
		var wafCfg waf.Config
		switch v := rawCfg.(type) {
		case waf.Config:
			// Already typed — direct assignment, no round-trip needed.
			wafCfg = v
		case map[string]any:
			// yaml-parsed form: marshal→unmarshal to populate the typed struct.
			buf, err := yaml.Marshal(v)
			if err != nil {
				return nil, fmt.Errorf("waf: marshal waf_config: %w", err)
			}
			if err := yaml.Unmarshal(buf, &wafCfg); err != nil {
				return nil, fmt.Errorf("waf: unmarshal waf_config: %w", err)
			}
		default:
			return nil, fmt.Errorf("waf: waf_config must be a map or waf.Config (got %T)", rawCfg)
		}
		// DropScore fallback: align WAF drop-weight with the global ban
		// threshold when the operator didn't set DropScore explicitly.
		if wafCfg.DropScore == 0 && banThreshold > 0 {
			wafCfg.DropScore = banThreshold
		}
		// ScoreFn closure — pipeline-single-writer model (tracker.go:75).
		// Safe: Update and ScoreFn run in the same goroutine, so the
		// returned *IPState pointer isn't concurrently mutated.
		wafCfg.ScoreFn = func(ip string, delta int) {
			if st := tracker.GetState(ip); st != nil {
				st.SetScore(st.GetScore()+delta, time.Now())
			}
		}
		return waf.NewWafProcessor(wafCfg)
	}
	// No WAF entry — pipeline runs without the rule-engine gate.
	return nil, nil
}
