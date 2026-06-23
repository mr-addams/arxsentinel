// ========================== Security processor — implements runtime.LineProcessor =========
//   Этот файл — VERBATIM PORT processLine (раньше в pipeline.go) в реализацию
//   runtime.LineProcessor для arx-core/pkg/runtime.
//
//   ЧТО ЗДЕСЬ:
//     - securityState      — opaque-состояние pipeline, передаётся в Process;
//                           живёт от Build() до Reload() (или до конца pipeline).
//     - securityProcessor  — тип-обёртка над state с импортируемым процессором;
//                           реализует runtime.LineProcessor (фабрика reuses).
//     - Process()          — verbatim port processLine; одна строка за один вызов.
//
//   КРИТИЧЕСКИ ВАЖНО: логика обработки байт-в-байт соответствует оригиналу.
//   Никаких улучшений/оптимизаций security-домена. integration 135/0 — gate.
//
//   ЧЕГО ЗДЕСЬ НЕТ:
//     - sinks: ими владеет engine через StreamSpec.Pipelines[i].Sinks.
//     - sources: то же.
//     - tracker-GC: запускается фабрикой один раз на группу.
//
//   СВЯЗЬ С DECISIONS.md (Flow 081):
//     - state.Scorer/Tracker/Matcher/Verifier — Product-side (DECISION Q1/Q2).
//     - Engine сам пишет в sinks и считает eventCount (engine.go Phase 2).
//     - SourceName/SourceType — engine передаёт через EventContext.

package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/mr-addams/arx-core/pkg/parser"
	"github.com/mr-addams/arx-core/pkg/plugin"
	coreruntime "github.com/mr-addams/arx-core/pkg/runtime"
	corechaincheck "github.com/mr-addams/arxsentinel/internal/core/chaincheck"
	"github.com/mr-addams/arxsentinel/internal/core/output"
	"github.com/mr-addams/arxsentinel/internal/core/scorer"
	"github.com/mr-addams/arxsentinel/internal/core/state"
	"github.com/mr-addams/arxsentinel/internal/core/whitelist"
	"github.com/mr-addams/arxsentinel/internal/sys/utils"
)

// ── securityState — opaque ProcessorState, передаваемый из factory.Build в Process ++++++++

// securityState хранит долгоживущие зависимости, разделяемые Process().
// Пересоздаётся при SIGHUP-reload (factory.Reload): Scorer и Matcher заменяются;
// Tracker и Verifier переживают reload (общий по группе).
// FakeBotScore и DNSVerifyTimeout отражают текущий конфиг.
//
// Sinks и SourceName/SourceType НЕ хранятся: sinks живут в engine.StreamSpec;
// SourceName/SourceType engine передаёт через EventContext.
type securityState struct {
	StreamName       string
	PipelineName     string
	PipelineIdx      int
	Tracker          *state.Tracker
	Scorer           *scorer.Scorer
	Matcher          *whitelist.Matcher
	Verifier         *whitelist.Verifier
	FakeBotScore     int
	DNSVerifyTimeout time.Duration
	// shared (runtime.SharedResources any) — читается через processor.shared, не в state.
}

// Compile-time гарантия: securityProcessor удовлетворяет runtime.LineProcessor.
var _ coreruntime.LineProcessor = (*securityProcessor)(nil)

// ── securityProcessor — реализация runtime.LineProcessor +++++++++++++++++++++++++++++++++++

// securityProcessor реализует runtime.LineProcessor. Process() — verbatim port
// processLine. Состояние читает из processor-полей + переданного securityState +
// processor.shared (для ChainChecker / WarningsWriter type-assert).
//
// metrics callbacks берутся из processor.shared.MetricsCallbacks (nil-safe).
type securityProcessor struct {
	shared coreruntime.SharedResources
}

// Process — VERBATIM PORT processLine из старого pipeline.go (строки 374–500).
// Структура шагов и порядок идентичны оригиналу; правки — только замены
// pipe.X → st.X / processor.shared.X (см. DECISIONS.md).
//
// Контракт runtime.LineProcessor:
//   - action.Skip=true → строка отбрасывается (не наш случай);
//   - action.Payload != nil → engine пишет в sinks и считает eventCount
//     (engine делает это сам, см. dispatchEntry).
//   - action.Payload == nil → строка прошла штатно, событий нет.
//
// Метрики (RecordLine / RecordInputLine) engine вызывает сам ДО Process.
// Наш долг — RecordThreat + RecordDetectorHit, которые Process знает семантически.
func (p *securityProcessor) Process(
	ctx context.Context,
	event *plugin.Event,
	ps coreruntime.ProcessorState,
	evctx coreruntime.EventContext,
) coreruntime.Action {
	// Defensive type-assert: должен всегда проходить, т.к. factory.Build возвращает *securityState.
	st, ok := ps.(*securityState)
	if !ok {
		return coreruntime.Action{Skip: true}
	}

	// Phase 2.2 (Flow 083): the runtime contract carries *plugin.Event; the
	// payload is parser-owned. We unwrap once here and reuse the LogEntry
	// throughout the existing verbatim port.
	entry := parser.UnwrapLogEntry(event)

	// Снимаем копии полей чтобы избежать data race при Reload (engine подменяет ps).
	// Использование локальных копий в Process — стандартный приём для in-place reload.
	streamName := st.StreamName
	pipelineName := st.PipelineName
	fakeBotScore := st.FakeBotScore
	dnsVerifyTimeout := st.DNSVerifyTimeout
	matcher := st.Matcher
	verifier := st.Verifier
	tracker := st.Tracker
	scorerRef := st.Scorer
	sourceName := evctx.SourceName
	sourceType := evctx.SourceType

	// Метрики callbacks — снимок структуры (atomic-чтение pointer-поля через copy).
	mc := p.shared.MetricsCallbacks

	utils.Log("PARSER", fmt.Sprintf("%s %s %s %d",
		entry.RealIP, entry.Method, entry.Path, entry.Status,
	), "debug")

	// ── Chain integrity check ─────────────────────────────────────────────────────────
	// Engine-ассерт ChainChecker / WarningsWriter из processor.shared (any → concrete).
	// nil → chain_guard disabled, пропускаем шаг.
	if cc, ok := p.shared.ChainChecker.(*corechaincheck.Checker); cc != nil && ok {
		if ww, ok := p.shared.WarningsWriter.(*output.WarningsWriter); ww != nil && ok {
			if result := cc.Check(entry.RemoteAddr); result != nil {
				_ = ww.WriteChainWarning(result, sourceName)
				utils.Log("CHAIN_WARN",
					fmt.Sprintf("%s-ip-as-client ip=%s cidr=%s source=%s",
						result.Kind, result.IP, result.MatchedCIDR, sourceName),
					"warning")
			}
		}
	}

	// ── Step 1: custom whitelist early-exit ──────────────────────────────────────────
	if matcher.IsWhitelistedIP(entry.RealIP) || matcher.IsWhitelistedUA(entry.UserAgent) || matcher.IsWhitelistedPath(entry.Path) {
		utils.Log("WHITELIST", "skipping via custom whitelist: "+entry.RealIP, "debug")
		return coreruntime.Action{}
	}

	// ── Steps 2–3: bot detection and verification ────────────────────────────────────
	isFakeBot := false
	var exemptSet map[string]struct{}
	if _, botCfg, matched := matcher.MatchBot(entry.UserAgent); matched {
		verifyCtx, cancelVerify := context.WithTimeout(ctx, dnsVerifyTimeout)
		verified, fake := verifier.Verify(verifyCtx, entry.RealIP, botCfg)
		cancelVerify()
		if verified {
			utils.Log("WHITELIST", "skipping: verified bot "+entry.RealIP, "debug")
			return coreruntime.Action{}
		}
		isFakeBot = fake

		if !verified && !isFakeBot && matched && len(botCfg.ExemptDetectors) > 0 {
			exemptSet = make(map[string]struct{}, len(botCfg.ExemptDetectors))
			for _, name := range botCfg.ExemptDetectors {
				exemptSet[name] = struct{}{}
			}
			utils.Log("WHITELIST", fmt.Sprintf("ua_only bot %s: exempt detectors %v", entry.RealIP, botCfg.ExemptDetectors), "debug")
		}
	}

	// ── Step 4: IP state tracking ─────────────────────────────────────────────────────
	ipState := tracker.Update(entry)

	// ── Step 4b: fake bot penalty ─────────────────────────────────────────────────────
	if isFakeBot {
		ipState.SetScore(ipState.GetScore()+fakeBotScore, time.Now())
		utils.Log("WHITELIST", fmt.Sprintf("fake bot %s +%d (fake bot score)", entry.RealIP, fakeBotScore), "warn")
	}

	// ── Scoring ───────────────────────────────────────────────────────────────────────
	level, score, modules, reason := scorerRef.Evaluate(ipState, entry, exemptSet)

	if level == "" {
		return coreruntime.Action{}
	}

	// Метрика RecordThreat (nil-safe).
	if mc != nil && mc.RecordThreat != nil {
		mc.RecordThreat(streamName, pipelineName, level)
	}
	for _, mod := range modules {
		if mc != nil && mc.RecordDetectorHit != nil {
			mc.RecordDetectorHit(streamName, pipelineName, mod)
		}
	}

	threat := plugin.ThreatEvent{
		Timestamp:  time.Now().UTC(),
		Level:      level,
		Stream:     streamName,
		Source:     sourceName,
		SourceType: sourceType,
		IP:         entry.RealIP,
		Score:      score,
		Modules:    modules,
		Reason:     reason,
	}
	utils.Log("THREAT", fmt.Sprintf("%s score=%d modules=%s reason=%q",
		entry.RealIP, score, strings.Join(modules, ","), reason), "warning")

	// Engine (dispatchEntry) сам сделает sink.Write + RecordOutputEvent;
	// eventCount.Add(1) engine выполнит только если level == "THREAT".
	// Phase 2.2 (Flow 083): Action carries a generic *plugin.Event whose
	// Payload is the product-owned ThreatEvent. The engine reads
	// Payload.Envelope.Level for metrics — we set it here.
	return coreruntime.Action{
		Payload: &plugin.Event{
			Envelope: plugin.Envelope{
				Source:     sourceName,
				SourceType: sourceType,
				Stream:     streamName,
				Level:      level,
				Timestamp:  threat.Timestamp,
			},
			Payload: &threat,
		},
	}
}

// Метрика RecordLine (на КАЖДОЙ строке, до Process) — engine зовёт сам (см.
// engine.go dispatchEntry). Здесь мы лишь сигналим, что эти метрики в
// коллбэке RecordLine уже покрывают product-вызовы metrics.RecordLine +
// metrics.RecordInputLine — это main.go в MetricsCallbacks-адаптере делает.
//
// RecordOutputEvent engine зовёт по факту sink.Write — main.go-адаптер внутри
// callback'а вызывает sinkTypeFromName(sink.Name) чтобы вычислить sinkType.
