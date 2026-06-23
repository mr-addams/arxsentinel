// ========================== pkg/runtime — generic Run engine =============================
//   Engine — обобщённый оркестратор стримов. Не знает ни про какие security-домены,
//   scoring, детекторы, цепочки прокси. Знает ТОЛЬКО контракт runtime:
//   - StreamSpec / PipelineSpec — структура стрима;
//   - LineProcessorFactory      — строитель per-pipeline state;
//   - LineProcessor             — обработчик одной строки;
//   - SharedResources / MetricsCallbacks / LogFn — runtime-примитивы.
//
//   БОУНДАРИ-ИНВАРИАНТ:
//     pkg/runtime НЕ импортирует ничего из arxsentinel/... (host-приложения).
//     Запрещены доменные security-слова в коде и комментариях — см. DECISIONS.md текущего flow.
//
//   ЧТО ЗДЕСЬ:
//     - Run                       — top-level: на каждый pipeline стрима стартует
//                                  runPipeline() в отдельной горутине;
//     - runPipeline               — isolated processing unit: Merge → Process → Sinks;
//     - dispatchEntry             — обработка одной строки через processor + fan-out в sinks.
//     - logTag / sourceMetadata   — мелкие утилиты форматирования лог-префиксов.
//
//   ЧЕГО ЗДЕСЬ НЕТ:
//     - Tracker-GC (запускает Product внутри factory.Build — runtime не знает о трекерах);
//     - проверки цепочек прокси, scoring, ранних выходов, блокировок — всё это
//       Product-build внутри factory;
//     - HTTP-сервера метрик — это Product-сайд.
//
//   КОНТРАКТ (для Product Phase 3):
//     factory ОБЯЗАН также реализовать LineProcessor (engine.Run делает type-assert).
//     Это намеренное разделение: factory = state-builder + reload-хук, processor = обработчик
//     одной строки. Один тип может реализовать оба интерфейса — тогда type-assert успешен.

package runtime

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	coreinput "github.com/mr-addams/arx-core/pkg/input"
	"github.com/mr-addams/arx-core/pkg/plugin"
)

// ++++++++++++++++++++++++++ Public top-level entry point +++++++++++++++++++++++++++++++++

// Run — точка входа в обобщённый runtime. Запускает один стрим: для каждого
// pipeline в streamSpec.Pipelines стартует runPipeline() в отдельной горутине.
//
// Контракт (важно для Product):
//   - factory ДОЛЖЕН реализовывать LineProcessor ПОВЕРХ LineProcessorFactory.
//     engine.Run делает type-assert в начале и возвращает ошибку, если factory
//     не реализует LineProcessor — это намеренная fail-fast защита.
//   - shared.MetricsCallbacks может быть nil — engine корректно игнорирует
//     каждый отдельный callback (nil-safe контракт).
//   - reloadCh: если не nil, каждое получение значения = SIGHUP-equivalent reload.
//   - logFn: если nil, используется no-op (engine не падает на nil-логгере).
//
// Поведение при завершении:
//   - ctx.Done() → drain оставшихся entries, потом возврат;
//   - все pipeline-горутины завершились → Run возвращает nil;
//   - panic в pipeline-горутине → recover в defer, ошибка уходит в logFn,
//     Run продолжает ждать оставшиеся pipeline'ы.
//
// Возврат:
//   - nil при штатном завершении всех pipelines;
//   - error если factory не реализует LineProcessor;
//   - ctx.Err() если ctx отменён и все pipeline'ы дренировали буферы.
func Run(
	ctx context.Context,
	streamSpec StreamSpec,
	factory LineProcessorFactory,
	shared SharedResources,
	reloadCh <-chan struct{},
	logFn LogFn,
) error {
	if logFn == nil {
		logFn = noopLogFn
	}

	// Тип-ассерт: factory ДОЛЖЕН быть одновременно LineProcessor.
	// Разделение интерфейсов осознанное (factory = state-builder, processor = row handler),
	// но в Phase 3 Product-factory реализует оба — здесь мы это явно проверяем.
	processor, ok := factory.(LineProcessor)
	if !ok {
		return fmt.Errorf("runtime.Run: factory %T must also implement LineProcessor", factory)
	}

	// Per-stream panic recovery: одна упавшая горутина стрима не должна уронить siblings.
	defer func() {
		if r := recover(); r != nil {
			logFn("RUNTIME", fmt.Sprintf("stream %q: panic recovered: %v", streamSpec.Name, r), "error")
		}
	}()

	logFn("RUNTIME", fmt.Sprintf("stream %q: starting (%d pipelines)", streamSpec.Name, len(streamSpec.Pipelines)), "info")

	var wg sync.WaitGroup
	for i := range streamSpec.Pipelines {
		i := i // capture loop var (для go 1.21- на всякий случай)
		pipe := streamSpec.Pipelines[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			runPipeline(ctx, streamSpec, pipe, factory, processor, shared, reloadCh, logFn)
		}()
	}
	wg.Wait()

	logFn("RUNTIME", fmt.Sprintf("stream %q: all pipelines done", streamSpec.Name), "info")
	return nil
}

// ++++++++++++++++++++++++++ runPipeline — single isolated pipeline +++++++++++++++++++++++

// runPipeline запускает один изолированный pipeline внутри стрима.
// Неблокирующий (вызывается из Run в горутине).
//
// Шаги:
//  1. factory.Build → ProcessorState (на ошибку — лог + выход);
//  2. строит evctx из имён stream/pipeline/source (см. sourceMetadata);
//  3. fan-in sources через coreinput.Merge;
//  4. select-loop: ctx.Done() | reloadCh | entry → dispatch через processor;
//
// Per-pipeline счётчики processedCount / eventCount — атомики, потому что
// stats-горутина их читает параллельно с диспетчером.
//
// SIGHUP-reload контракт:
//   - factory.Reload(old, ctx) → новый state, engine атомарно подменяет;
//   - на каждый sink, реализующий Reloader, вызывается Reload() (например,
//     FileSink для ротации лог-файлов на месте).
func runPipeline(
	ctx context.Context,
	streamSpec StreamSpec,
	pipe PipelineSpec,
	factory LineProcessorFactory,
	processor LineProcessor,
	shared SharedResources,
	reloadCh <-chan struct{},
	logFn LogFn,
) {
	// Per-pipeline panic recovery: паника в pipeline-горутине не должна уронить весь стрим.
	defer func() {
		if r := recover(); r != nil {
			logFn("RUNTIME", fmt.Sprintf("%s: panic recovered: %v", logTag(streamSpec.Name, pipe.Name), r), "error")
		}
	}()

	tag := logTag(streamSpec.Name, pipe.Name)

	// 1. Строим per-pipeline state через factory.Build.
	ps, err := factory.Build(streamSpec.Name, pipe.Name, pipe.Idx, shared)
	if err != nil {
		logFn("RUNTIME", fmt.Sprintf("%s: factory.Build error: %v", tag, err), "error")
		return
	}

	// 2. Per-pipeline atomics.
	var processedCount atomic.Int64
	var eventCount atomic.Int64

	// 3. EventContext — статические поля для каждого вызова Process.
	evctx := EventContext{
		StreamName:   streamSpec.Name,
		PipelineName: pipe.Name,
		PipelineIdx:  pipe.Idx,
	}
	if len(pipe.Sources) > 0 {
		evctx.SourceName, evctx.SourceType = sourceMetadata(pipe.Sources)
	}

	// 4. Buffer size: per-stream override → 0 → дефолт.
	bufSize := streamSpec.BufferSize
	if bufSize == 0 {
		bufSize = defaultBufferSize
	}

	// 5. Fan-in: каждый Source стартует в своей горутине, Merge возвращает общий канал.
	//    input.LogFn и runtime.LogFn — разные именованные типы, поэтому явная конвертация.
	entries := coreinput.Merge(ctx, pipe.Sources, bufSize, coreinput.LogFn(logFn))

	logFn("RUNTIME", fmt.Sprintf("%s: pipeline started (sources=%d sinks=%d)", tag, len(pipe.Sources), len(pipe.Sinks)), "info")

	// 6. Stats-горутина: периодический structured log + UpdateGauges callback (если есть).
	statsInterval := streamSpec.StatsInterval
	if statsInterval == 0 {
		statsInterval = defaultStatsInterval
	}
	go runStats(ctx, tag, &processedCount, &eventCount, shared, streamSpec, pipe, statsInterval, logFn)

	// 7. Главный select-цикл: ctx | reload | entry.
	for {
		select {
		case <-ctx.Done():
			// Sources останавливаются на ctx.Done(), Merge закрывает entries, когда
			// все sources вышли. Дренируем оставшиеся entries в processLine.
			// Используем context.Background() (а не ctx): ctx уже отменён, иначе любой
			// downstream ctx.WithTimeout(ctx, ...) был бы сразу отменён.
			logFn("RUNTIME", fmt.Sprintf("%s: shutdown signal, draining buffer...", tag), "info")
			for entry := range entries {
				dispatchEntry(context.Background(), entry, processor, ps, evctx, pipe.Sinks, shared, &processedCount, &eventCount, logFn)
			}
			logFn("RUNTIME", fmt.Sprintf("%s: drain done", tag), "info")
			return

		case <-reloadCh:
			// SIGHUP-equivalent reload. Product reads config inside factory.Reload.
			newPs, err := factory.Reload(ps, ctx)
			if err != nil {
				logFn("RELOAD", fmt.Sprintf("%s: factory.Reload error: %v", tag, err), "warn")
				continue
			}
			ps = newPs
			// Reload каждого sink, реализующего Reloader (например, FileSink для log-rotation).
			for _, sink := range pipe.Sinks {
				if r, ok := sink.(Reloader); ok {
					if err := r.Reload(); err != nil {
						logFn("RELOAD", fmt.Sprintf("%s: sink %q reload error: %v", tag, sink.Name(), err), "warn")
					}
				}
			}
			logFn("RELOAD", fmt.Sprintf("%s: reloaded", tag), "info")

		case entry, ok := <-entries:
			if !ok {
				// Канал закрыт — все sources вышли без panic (или после shutdown).
				logFn("RUNTIME", fmt.Sprintf("%s: channel closed, exiting", tag), "info")
				return
			}
			dispatchEntry(ctx, entry, processor, ps, evctx, pipe.Sinks, shared, &processedCount, &eventCount, logFn)
		}
	}
}

// ++++++++++++++++++++++++++ dispatchEntry — one-row processing ++++++++++++++++++++++++++++

// dispatchEntry прогоняет одну строку через processor и fan-out результата в sinks.
//
// Контракт (важно для Product):
//   - action.Skip=true  → строка отбрасывается (filter-семантика);
//   - action.Payload != nil → пишем событие в КАЖДЫЙ sink (fan-out, порядок не важен);
//   - nil payload после non-Skip → строка прошла штатно, событий нет.
//
// Phase 2.2 (Flow 083 / RESOLVED-Q9): action carries *plugin.Event (envelope
// + opaque payload). The engine reads envelope.Level for metrics (P1) and
// forwards the whole event to each sink. The engine never inspects the
// payload — that is the owning plugin's responsibility.
//
// Метрики:
//   - RecordLine: на КАЖДОЙ обработанной строке (включая Skip=true — это «line received»);
//   - RecordThreat: только при Payload != nil (событийная метрика);
//   - RecordOutputEvent: на каждом успешном sink.Write;
//   - processedCount / eventCount — атомики, читаются stats-горутиной.
//
// Ошибки sink.Write НЕ останавливают pipeline — логируются, цикл продолжается.
// Это намеренное решение: один упавший sink не должен отключать весь pipeline.
func dispatchEntry(
	ctx context.Context,
	entry *plugin.Event,
	processor LineProcessor,
	ps ProcessorState,
	evctx EventContext,
	sinks []plugin.Sink,
	shared SharedResources,
	processedCount, eventCount *atomic.Int64,
	logFn LogFn,
) {
	processedCount.Add(1)

	// Метрика "line received" — на каждой строке, ДО Process (даже если Skip).
	if cb := shared.MetricsCallbacks; cb != nil && cb.RecordLine != nil {
		cb.RecordLine(evctx.StreamName, evctx.PipelineName, evctx.SourceName, evctx.SourceType)
	}

	action := processor.Process(ctx, entry, ps, evctx)

	if action.Skip {
		return
	}

	if action.Payload == nil {
		return
	}

	// Событие: пишем в каждый sink, считаем eventCount только на THREAT-уровне.
	// Engine читает envelope.Level — envelope is the only field the engine
	// is allowed to interpret (P1); payload is opaque.
	level := action.Payload.Level
	if level == "THREAT" {
		eventCount.Add(1)
	}
	if cb := shared.MetricsCallbacks; cb != nil && cb.RecordThreat != nil {
		cb.RecordThreat(evctx.StreamName, evctx.PipelineName, level)
	}
	for _, sink := range sinks {
		if err := sink.Write(ctx, action.Payload); err != nil {
			logFn("SINK", fmt.Sprintf("%s: sink %q write error: %v",
				logTag(evctx.StreamName, evctx.PipelineName), sink.Name(), err), "error")
			continue
		}
		if cb := shared.MetricsCallbacks; cb != nil && cb.RecordOutputEvent != nil {
			cb.RecordOutputEvent(evctx.StreamName, evctx.PipelineName, sink.Name())
		}
	}
}

// ++++++++++++++++++++++++++ runStats — periodic stats ++++++++++++++++++++++++++++++++++++

// runStats — периодический structured-лог counters + UpdateGauges callback (nil-safe).
// Завершается при ctx.Done(). Tick интервал берётся из StreamSpec.StatsInterval
// (0 → defaultStatsInterval).
//
// Контракт UpdateGauges: если Product регистрирует callback, ему передаются
// processedCount и eventCount (current snapshots). Если нет — пропускаем.
func runStats(
	ctx context.Context,
	tag string,
	processedCount, eventCount *atomic.Int64,
	shared SharedResources,
	streamSpec StreamSpec,
	pipe PipelineSpec,
	interval time.Duration,
	logFn LogFn,
) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			processed := processedCount.Load()
			events := eventCount.Load()
			logFn("STATS", fmt.Sprintf("%s processed=%d events=%d", tag, processed, events), "info")
			if cb := shared.MetricsCallbacks; cb != nil && cb.UpdateGauges != nil {
				cb.UpdateGauges(streamSpec.Name, pipe.Name, processed, events)
			}
		}
	}
}

// ++++++++++++++++++++++++++ Helpers (private) +++++++++++++++++++++++++++++++++++++++++++++

// logTag формирует human-readable лог-префикс для пары (stream, pipeline).
// Совпадает по формату с product-side pipelineLogTag (helpers.go) —
// чтобы логи из core-runtime и из product-сайда выглядели одинаково.
//
// Формат:
//   - оба пустые → "(default)";
//   - pipelineName пустой → "stream %q";
//   - оба заданы → "stream %q pipeline %q".
func logTag(streamName, pipelineName string) string {
	if streamName == "" && pipelineName == "" {
		return "(default)"
	}
	if pipelineName == "" {
		return fmt.Sprintf("stream %q", streamName)
	}
	return fmt.Sprintf("stream %q pipeline %q", streamName, pipelineName)
}

// sourceMetadata извлекает (name, type) из первого source в списке.
//
// Type определяется префиксом имени source.Name(): "file:" → "file", иначе → "stdin".
// Это контракт-нейтральное правило, известное arx-core/pkg/source (имя с "file:" —
// стандартное именование file-source-plugin), поэтому engine может его применить,
// не залезая в security/domain-домен.
//
// Длина списка > 0 уже проверена вызывающим кодом.
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

// ++++++++++++++++++++++++++ Defaults & no-op fallback +++++++++++++++++++++++++++++++++++++

// defaultBufferSize — fallback-размер канала Merge, если StreamSpec.BufferSize == 0.
// Hardcoded внутри engine, не экспортируется: это деталь реализации engine,
// а не runtime-контракт (Product всегда может задать StreamSpec.BufferSize явно).
const defaultBufferSize = 1000

// defaultStatsInterval — fallback-период stats-лога, если StreamSpec.StatsInterval == 0.
// 30s выбрано как разумный баланс между свежестью и шумом в логе.
const defaultStatsInterval = 30 * time.Second

// noopLogFn — запасной LogFn на случай, если Product передал nil.
// Все runtime-вызовы logFn корректны с noop (тип LogFn = func(...)).
func noopLogFn(_, _, _ string) {
	// deliberately empty
}
