// ========================== pkg/runtime — RunOptions ====================================
//   RunOptions — параметры КОНТРАКТА ЯДРА как runtime-примитивов.
//
//   ЭТО НЕ CONFIG. RunOptions — это набор голых значений, которые Engine берёт
//   при старте и трактует так же, как http.Server{Addr, ReadTimeout, Handler}:
//   примитивы, не словарь. Никакого YAML, никакого map[string]any, никакого
//   reflect для разбора.
//
//   Product читает YAML/config-структуры → собирает RunOptions → передаёт в Engine.Run.
//   Сам Engine.Run НЕ знает слова "config" и не пытается его парсить.
//
//   ЧТО ЗДЕСЬ:
//     - RunOptions — три примитива: буфер, shutdown, tracker-group.
//
//   ЧЕГО ЗДЕСЬ НЕТ:
//     - Никаких ссылок на internal/sys/config или YAML-структуры.
//     - Никаких значений по умолчанию (defaults живут в Engine.Run, не здесь).

package runtime

import "time"

// ++++++++++++++++++++++++++ RunOptions — общие параметры Engine ++++++++++++++++++++++++++

// RunOptions — общие параметры, которые Engine.Run принимает в дополнение к
// []StreamSpec. Это параметры-примитивы для оркестрации runtime'а:
//
//   - BufferSize      — размер каналов между ступенями (если не переопределён
//                       в StreamSpec.BufferSize, Engine берёт это значение).
//   - ShutdownTimeout — максимум времени на graceful shutdown всех стримов;
//                       при превышении Engine.Run возвращает context.DeadlineExceeded.
//   - TrackerGroup    — имя tracker-pool'а (см. arx-core/pkg/dedup и Phase 2: scoring pool).
//
// Все поля обязательны: если Product не знает значение, он ставит 0 и
// Engine.Run применит свои разумные defaults (документированы в Phase 2).
type RunOptions struct {
	BufferSize      int
	ShutdownTimeout time.Duration
	TrackerGroup    string
}
