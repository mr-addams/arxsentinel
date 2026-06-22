// ========================== pkg/runtime — generic Stream/Pipeline spec =====================
//   StreamSpec и PipelineSpec — это ЧИСТЫЕ DTO контракта ядра.
//
//   БОУНДАРИ-ИНВАРИАНТ:
//     Эти структуры описывают уже СОБРАННЫЙ (ready-to-run) пайплайн. Они НЕ содержат:
//       - ссылок на config / YAML / env / secrets;
//       - имён detector'ов, уровней эскалации, пороговых значений;
//       - блок-листов, трекеров, проверок цепочек прокси.
//
//   Product собирает их через builder.go (Phase 2): читает YAML, инстанцирует Source'ы,
//   Detector'ы, Sink'и, потом передаёт ГОТОВЫЙ []StreamSpec в runtime.Run.
//
//   ЧТО ЗДЕСЬ:
//     - StreamSpec   — параметры одного стрима (буфер, shutdown, список пайплайнов).
//     - PipelineSpec — один пайплайн внутри стрима (имя, индекс, источники, приёмники).
//
//   ЧЕГО ЗДЕСЬ НЕТ:
//     - Ссылок на internal/sys/config — это config-домен Product'а.
//     - Detector'ов — Product-built, передаются через замыкание в factory.Build.

package runtime

import (
	"time"

	"github.com/mr-addams/arx-core/pkg/plugin"
)

// ++++++++++++++++++++++++++ PipelineSpec — один пайплайн внутри стрима ++++++++++++++++++

// PipelineSpec — параметры контракта для одного pipeline внутри стрима.
//
// Sources — массив уже СОБРАННЫХ plugin.Source (Product собрал их через
// builder.go, runtime их не строит). Массив допускает несколько источников —
// merge-логика для n источников в Phase 2.
//
// Sinks — массив уже СОБРАННЫХ plugin.Sink. Каждый ThreatEvent пишется во ВСЕ sinks
// (fan-out), порядок не важен.
//
// Detector'ы НЕ входят в PipelineSpec — Product передаёт их через замыкание,
// которое попадёт в LineProcessorFactory.Build. Это намеренное разделение:
//   - PipelineSpec — статический контракт (что запускаем);
//   - factory.Build — динамика (как именно обрабатываем, включая детекторы).
//
// Name используется в логах и метриках (axis pipeline_name).
// Idx — позиция pipeline в StreamSpec.Pipelines (0..len-1), пробрасывается
//
//	в EventContext.PipelineIdx. Дублируем для удобства итерации без zip.
type PipelineSpec struct {
	Name    string
	Idx     int
	Sources []plugin.Source
	Sinks   []plugin.Sink
}

// ++++++++++++++++++++++++++ StreamSpec — параметры одного стрима ++++++++++++++++++++++++

// StreamSpec — параметры контракта ядра для одного стрима.
//
// Name — стабильный идентификатор стрима, используется в логах и метриках.
// TrackerGroup — имя группы tracker'а для tracker-pool'а (Phase 2: scoring pool).
//
//	Передаётся Product'ом, runtime не интерпретирует.
//
// BufferSize — размер каналов между ступенями пайплайна (chan *LogEntry).
//
//	           Маленькие значения → back-pressure; большие → память. См. architect-081-impl.
//	ShutdownTimeout — максимальное время graceful shutdown всех горутин стрима.
//	StatsInterval  — период (time.Duration) для periodic stats log + gauge update;
//	                 0 → дефолт 30s внутри engine.Run. Добавлено в Phase 2
//	                 (engine.go нужен интервал для stats-горутины — это часть
//	                 generic runtime-контракта, не security-домен Product'а).
//	Pipelines — список пайплайнов, которые стартуют параллельно как часть стрима.
//
//	Все эти поля — runtime-примитивы (по аналогии с http.Server{Addr, ReadTimeout}),
//	а не продуктовый конфиг. Product читает YAML и СТРОИТ StreamSpec из примитивов
//	(см. DECISIONS.md).
type StreamSpec struct {
	Name            string
	TrackerGroup    string
	BufferSize      int
	ShutdownTimeout time.Duration
	StatsInterval   time.Duration
	Pipelines       []PipelineSpec
}
