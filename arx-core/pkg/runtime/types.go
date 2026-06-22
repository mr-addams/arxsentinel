// ========================== pkg/runtime — generic contract types =========================
//   Этот пакет определяет ЧИСТЫЙ КОНТРАКТ между core-runtime и Product.
//
//   БОУНДАРИ-ИНВАРИАНТ:
//     pkg/runtime импортирует ТОЛЬКО:
//       - stdlib (context, time, ...)
//       - github.com/mr-addams/arx-core/pkg/plugin (общие DTO: LogEntry, ThreatEvent, Source, Sink)
//     Запрещено импортировать что-либо из основного проекта (внутренние пакеты host-приложения).
//     Запрещены security-домен и config-слова в импортах и именах — см. DECISIONS.md текущего flow.
//
//   Контракт описывает ТОЛЬКО обобщённые runtime-примитивы. Здесь НЕТ логики detector'ов,
//   scoring'а, проверки цепочек прокси, пороговых значений и блокировок. Это всё Product-built
//   и передаётся через замыкания LineProcessorFactory.Build, а Core-runtime их не знает.
//
//   ЧТО ЗДЕСЬ:
//     - Action, EventContext, ProcessorState — то, что пробрасывается через каждый Process().
//     - LineProcessor — интерфейс одной ступени пайплайна.
//     - LineProcessorFactory — строитель per-pipeline состояния и хук reload.
//     - Reloader — интерфейс фонового обновления состояния процессора.
//     - SharedResources — opaque-контейнер, Product заполняет и передаёт,
//       Core-runtime не дёргает его поля напрямую.
//     - MetricsCallbacks — набор nil-safe callbacks для метрик.
//     - LogFn — обобщённый тип лог-функции.
//
//   ЧЕГО ЗДЕСЬ НЕТ:
//     - Никаких security-домен слов в именах типов и полей.
//     - Никаких ссылок на config / YAML / env.
//     - Никакой оркестрации горутин и каналов — это Phase 2 (engine.Run).

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
// ThreatEvent НЕ nil → пайплайн публикует событие во все Sinks (после финальной ступени).
// ThreatEvent == nil → строка прошла как обычный трафик, событий нет.
//
// Action — value type, без мьютексов. Один LineProcessor может вернуть
// только одно (Skip, ThreatEvent) на каждый вызов Process.
type Action struct {
	Skip        bool
	ThreatEvent *plugin.ThreatEvent
}

// ++++++++++++++++++++++++++ EventContext — контекст события для Process +++++++++++++++++++

// EventContext — служебные поля, описывающие где в пайплайне сейчас идёт строка.
// LineProcessor получает это как параметр и использует для метрик/логов.
//
// PipelineIdx — позиция pipeline в стриме (0..len(StreamSpec.Pipelines)-1).
// SourceName / SourceType — пробрасываются из Source.Manifest / Source.Name.
type EventContext struct {
	StreamName   string
	PipelineName string
	SourceName   string
	SourceType   string
	PipelineIdx  int
}

// ++++++++++++++++++++++++++ ProcessorState — opaque состояние пайплайна ++++++++++++++++++

// ProcessorState — opaque значение, которое Product хранит между вызовами Process().
//
// Core-runtime трактует его как `any` и не пытается интерпретировать.
// Это снимает необходимость тащить security-типы в этот пакет — Product может
// хранить внутри что угодно (блок-лист, счётчик, индекс).
//
// Используется дважды:
//   - Возвращается из LineProcessorFactory.Build один раз на старте pipeline.
//   - Передаётся в каждый вызов Process как параметр.
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
// Core-runtime НЕ интерпретирует возвращённый Action — это обобщённый runtime DTO,
// который downstream (engine.Run в Phase 2) превратит в Pass/Drop/Emit.
type LineProcessor interface {
	Process(ctx context.Context, entry *plugin.LogEntry, state ProcessorState, evctx EventContext) Action
}

// ++++++++++++++++++++++++++ LineProcessorFactory — строитель state +++++++++++++++++++++++

// LineProcessorFactory — строитель per-pipeline состояния.
//
// Build вызывается Core-runtime ОДИН раз при старте pipeline.
//   - Внутри Build Product обычно:
//       1) Резолвит detectors/trackers по имени (через PluginRegistry).
//       2) Открывает нужные ресурсы (blocklist, chain-check и т.п. — НЕ в runtime).
//       3) Возвращает opaque state, который будет жить до Reload.
//
// Reload вызывается по сигналу (SIGHUP, ConfigMap reload в k8s) —
//   возвращает НОВЫЙ state, Core-runtime атомарно подменит старый.
//
// Оба метода обязаны быть thread-safe (могут вызываться из разных горутин при
// одновременном Reload нескольких pipeline'ов).
type LineProcessorFactory interface {
	Build(streamName, pipeName string, pipeIdx int, shared SharedResources) (ProcessorState, error)
	Reload(old ProcessorState, ctx context.Context) (ProcessorState, error)
}

// ++++++++++++++++++++++++++ Reloader — фоновый hot-reload +++++++++++++++++++++++++++++++++

// Reloader — опциональный интерфейс для фонового reload'а.
// Продукт может реализовать его на factory, чтобы переодически
// (по таймеру или SIGHUP) перестраивать state без остановки pipeline.
//
// Это ОТДЕЛЬНЫЙ интерфейс от LineProcessorFactory.Reload —
// он не принимает old state, потому что Product сам его где-то хранит
// и сам решает, как достать "текущий" state.
type Reloader interface {
	Reload() error
}

// ++++++++++++++++++++++++++ LogFn — обобщённый тип лог-функции +++++++++++++++++++++++++++

// LogFn — обобщённый тип функции логирования, принимаемый runtime'ом.
//
// Подпись `(tag, msg, level string)` совпадает с noop-логгером в pkg/tail
// и с тем, что Product использует в остальных местах — это общий контракт
// логгера, не зависящий от конкретного пакета ввода/вывода.
//
// Core-runtime вызывает LogFn(tag, msg, level) с произвольным tag
// (например "runtime", "engine", "pipeline") и level ∈ {"info","warn","error","debug"}.
// Product может обернуть LogFn в любой свой логгер.
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
//
// Контракт: заполняется ОДИН раз на старте Engine (Product собирает по PluginRegistry),
// далее только читается.
type SharedResources struct {
	BlocklistManager any
	ChainChecker     any
	WarningsWriter   any
	MetricsCallbacks *MetricsCallbacks
}

// ++++++++++++++++++++++++++ MetricsCallbacks — nil-safe runtime callbacks ++++++++++++++++

// MetricsCallbacks — набор callback'ов, которые Core-runtime вызывает на ключевых
// точках обработки строки.
//
// Правила вызова (для Core-runtime, реализация — Phase 2):
//   - ПЕРЕД каждым вызовом ОБЯЗАНА быть проверка:
//         if cb != nil && cb.<Field> != nil { cb.<Field>(...) }
//   - То есть Core-runtime никогда не падает, если Product не зарегистрировал
//     конкретный callback — это nil-safe контракт.
//
// Сигнатура Record* функций:
//   - streamName, pipelineName — обязательные axis-метки.
//   - sourceName, sourceType, sinkName, sinkType — заполняются, когда известны.
//   - level ∈ {"WARN","THREAT"} для RecordThreat; moduleName для RecordDetectorHit.
//   - trackedIPs / suspicious — gauge-значения для UpdateGauges.
//
// Все callbacks выполняются синхронно в горутине pipeline'а — реализации
// обязаны быть неблокирующими (типично — atomic counter в Prometheus registry).
type MetricsCallbacks struct {
	RecordLine        func(streamName, pipelineName, sourceName, sourceType string)
	RecordThreat      func(streamName, pipelineName, level string)
	RecordInputLine   func(streamName, pipelineName, sourceName, sourceType string)
	RecordDetectorHit func(streamName, pipelineName, moduleName string)
	RecordOutputEvent func(streamName, pipelineName, sinkName, sinkType string)
	UpdateGauges      func(streamName, pipelineName string, trackedIPs, suspicious int64)
}
