// ========================== pkg/runtime — generic contract types =========================
//   Этот пакет определяет ЧИСТЫЙ КОНТРАКТ между core-runtime и Product.
//
//   БОУНДАРИ-ИНВАРИАНТ:
//     pkg/runtime импортирует ТОЛЬКО:
//       - stdlib (context, time, ...)
//       - github.com/mr-addams/arx-core/pkg/plugin (общие DTO: Source, Sink, Event, Envelope)
//     Запрещено импортировать что-либо из основного проекта (внутренние пакеты host-приложения).
//     Запрещены security-домен и config-слова в импортах и именах — см. DECISIONS.md текущего flow.
//
//   Контракт описывает ТОЛЬКО обобщённые runtime-примитивы.
//
//   Phase 2.2 (Flow 083 / RESOLVED-Q9 / RESOLVED-Q12):
//     - LineProcessor.Process receives the generic *plugin.Event; payload is
//       plugin-owned (typically *parser.LogEntry), wrapped via WrapLogEntry on
//       the source side and UnwrapLogEntry on the product side.
//     - Action carries *plugin.Event as Payload — the engine reads
//       Action.Payload.Envelope.Level for metrics (P1: envelope is the only
//       field the engine is allowed to interpret) and forwards
//       Action.Payload to each sink as *plugin.Event.
//     - Decision 7 still holds: signatures of Run/Build/Reload/Process are
//       stable; only the argument type changes (LogEntry → Event).

package runtime

import (
	"context"

	"github.com/mr-addams/arx-core/pkg/plugin"
)

// ++++++++++++++++++++++++++ Action — результат обработки строки ++++++++++++++++++++++++++

// Action — решение, которое LineProcessor возвращает на одну строку.
//
// Skip=true → строка отбрасывается дальше по пайплайну (filter/gate-семантика).
// Skip=false → строка идёт дальше как есть.
//
// Payload != nil → пайплайн публикует событие во все Sinks (после финальной ступени).
// Payload == nil → строка прошла как обычный трафик, событий нет.
//
// Action — value type, без мьютексов. Один LineProcessor может вернуть
// только одно (Skip, Payload) на каждый вызов Process.
//
// Phase 2.2: Payload is *plugin.Event (the generic envelope + opaque payload).
// The engine reads Action.Payload.Envelope.Level for metrics; concrete
// payload-shape concerns live with the plugin that produced it.
type Action struct {
	Skip    bool
	Payload *plugin.Event
}

// ++++++++++++++++++++++++++ EventContext — контекст события для Process +++++++++++++++++++

// EventContext — служебные поля, описывающие где в пайплайне сейчас идёт строка.
// LineProcessor получает это как параметр и использует для метрик/логов.
type EventContext struct {
	StreamName   string
	PipelineName string
	SourceName   string
	SourceType   string
	PipelineIdx  int
}

// ++++++++++++++++++++++++++ ProcessorState — opaque состояние пайплайна ++++++++++++++++++

// ProcessorState — opaque значение, которое Product хранит между вызовами Process().
type ProcessorState = any

// ++++++++++++++++++++++++++ LineProcessor — интерфейс ступени пайплайна +++++++++++++++++

// LineProcessor — одна ступень пайплайна, через которую проходит каждая строка.
//
// Контракт вызова:
//   - Вызывается последовательно в одной горутине pipeline.
//   - state — opaque значение, ранее возвращённое factory.Build() для этого pipeline.
//   - evctx — статические поля (stream, pipeline, source), инициализируются один раз
//     на старте pipeline и не меняются от строки к строке.
//   - Должен быть детерминированным для одного и того же (entry, state).
//
// Phase 2.2: entry is *plugin.Event; the processor may unwrap the payload
// (UnwrapLogEntry) to reach the parser-owned LogEntry, score it, and
// replace the payload before returning.
type LineProcessor interface {
	Process(ctx context.Context, entry *plugin.Event, state ProcessorState, evctx EventContext) Action
}

// ++++++++++++++++++++++++++ LineProcessorFactory — строитель state +++++++++++++++++++++++

// LineProcessorFactory — строитель per-pipeline состояния.
//
// Build вызывается Core-runtime ОДИН раз при старте pipeline.
//   - Внутри Build Product обычно:
//     1) Резолвит detectors/trackers по имени (через PluginRegistry).
//     2) Открывает нужные ресурсы (blocklist, chain-check и т.п. — НЕ в runtime).
//     3) Возвращает opaque state, который будет жить до Reload.
//
// Reload вызывается по сигналу (SIGHUP, ConfigMap reload в k8s) —
// возвращает НОВЫЙ state, Core-runtime атомарно подменит старый.
//
// Оба метода обязаны быть thread-safe (могут вызываться из разных горутин при
// одновременном Reload нескольких pipeline'ов).
type LineProcessorFactory interface {
	Build(streamName, pipeName string, pipeIdx int, shared SharedResources) (ProcessorState, error)
	Reload(old ProcessorState, ctx context.Context) (ProcessorState, error)
}

// ++++++++++++++++++++++++++ Reloader — фоновый hot-reload +++++++++++++++++++++++++++++++++

// Reloader — опциональный интерфейс для фонового reload'а.
type Reloader interface {
	Reload() error
}

// ++++++++++++++++++++++++++ LogFn — обобщённый тип лог-функции +++++++++++++++++++++++++++

// LogFn — обобщённый тип функции логирования, принимаемый runtime'ом.
//
// Подпись `(tag, msg, level string)` совпадает с noop-логгером в pkg/tail
// и с тем, что Product использует в остальных местах — это общий контракт
// логгера, не зависящий от конкретного пакета ввода/вывода.
type LogFn func(tag, msg, level string)

// ++++++++++++++++++++++++++ SharedResources — opaque runtime-примитивы +++++++++++++++++++

// SharedResources — opaque контейнер, который Product заполняет и передаёт
// в каждый LineProcessorFactory.Build.
//
// Core-runtime НЕ дёргает эти поля — он только пробрасывает структуру как
// параметр, чтобы Product-замыкания внутри Build могли получить к ним доступ.
//
// Конкретные типы полей:
//   - BlocklistManager, ChainChecker, WarningsWriter — `any` чтобы не затаскивать
//     сюда security-домен (имена из domain-логики Product — запрещены в этом пакете).
//   - MetricsCallbacks — структура ниже; Core-runtime дёргает ТОЛЬКО эти callbacks
//     (если они не nil), даже если Product кладёт в SharedResources ещё что-то своё.
type SharedResources struct {
	BlocklistManager any
	ChainChecker     any
	WarningsWriter   any
	MetricsCallbacks *MetricsCallbacks
}

// ++++++++++++++++++++++++++ MetricsCallbacks — nil-safe runtime callbacks ++++++++++++++++

// MetricsCallbacks — набор callback'ов, которые Core-runtime вызывает на ключевых
// точках обработки строки.
type MetricsCallbacks struct {
	RecordLine        func(streamName, pipelineName, sourceName, sourceType string)
	RecordThreat      func(streamName, pipelineName, level string)
	RecordInputLine   func(streamName, pipelineName, sourceName, sourceType string)
	RecordDetectorHit func(streamName, pipelineName, moduleName string)
	RecordOutputEvent func(streamName, pipelineName, sinkName string)
	UpdateGauges      func(streamName, pipelineName string, trackedIPs, suspicious int64)
}