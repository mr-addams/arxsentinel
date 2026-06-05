// Package dedup предоставляет общий механизм дедупликации событий
// для всех executor-ов проекта ArxSentinel.
//
// Назначение: предотвратить повторное применение блокировки
// к одному и тому же ключу (IP, fingerprint, token) в течение
// заданного временного окна TTL.
//
// Идея: каждый executor (cloudflare, mikrotik, nginx) получал свою
// локальную map с одинаковой логикой очистки по TTL. Это приводило
// к дублированию кода и разному поведению между executor-ами.
// Decision 4 флоу 061 фиксирует единый пакет pkg/dedup.
//
// API:
//   - Contains(key) — чистый lookup: true, если ключ уже в окне и TTL не истёк.
//     Не имеет side-effect и безопасен для повторных вызовов.
//   - Mark(key)     — записывает/продлевает ключ в окне (side-effect).
//     Вызывать ТОЛЬКО после успешного действия, чтобы flaky-ошибки
//     upstream (RouterOS, CF) не оставляли IP заблокированным на TTL.
//   - IsDuplicate(key) — convenience-обёртка: Contains→Mark→false / Contains→true.
//     Подходит для сценариев, где side-effect ошибки не критичен.
//
// Использование (рекомендуемый паттерн — flaky-safe):
//
//	w := dedup.NewWindow(5 * time.Minute)
//	if w.Contains("1.2.3.4") {
//	    // уже банили недавно — пропускаем
//	    return nil
//	}
//	// ...выполнить дорогостоящее действие (Add/Block)...
//	if err := doAction(); err != nil {
//	    return err  // ключ НЕ отмечен, повторная попытка дойдёт снова
//	}
//	w.Mark("1.2.3.4")  // помечаем ТОЛЬКО после успеха
package dedup

import (
	"sync"
	"time"
)

// Window — потокобезопасное окно дедупликации с TTL.
//
// Нулевой TTL (NewWindow(0)) полностью отключает дедупликацию:
// Contains всегда возвращает false, Mark — no-op.
// Это позволяет через конфигурацию executor-а включать/выключать
// dedup без изменения кода.
//
// nil receiver безопасен: (*Window)(nil).Contains/Mark/IsDuplicate
// не паникуют и ведут себя как выключенный dedup.
// Это упрощает код executor-ов — им не нужно проверять, инициализирован ли window.
type Window struct {
	// ttl — время жизни записи. Ноль означает "всегда пропускать".
	// Хранится в поле, а не вычисляется заново, чтобы пользователь
	// мог в будущем добавить смену TTL на лету без правки вызывающего кода.
	ttl time.Duration

	// entries — карта "ключ -> момент истечения".
	// Значение — абсолютный момент, до которого ключ считается активным.
	// Это упрощает чтение: не нужно хранить duration отдельно от now.
	entries map[string]time.Time

	// mu защищает entries. sync.Mutex, а не sync.RWMutex, потому что
	// в типичном сценарии (один детектор → один executor) чтения
	// не преобладают критически, а Lock/Unlock дешевле по памяти.
	// Кроме того, при апдейте записи мы берём Lock на запись.
	mu sync.Mutex

	// nowFn — функция получения текущего времени. По умолчанию time.Now.
	// Вынесена в поле для тестирования: в тестах подменяем на fake clock
	// и не зависим от реального таймера.
	nowFn func() time.Time
}

// NewWindow создаёт новое окно дедупликации с заданным TTL.
//
// ttl == 0 отключает дедупликацию (Contains всегда false, Mark — no-op).
// ttl < 0 трактуется как 0 (защита от опечаток в конфиге).
func NewWindow(ttl time.Duration) *Window {
	if ttl < 0 {
		ttl = 0
	}
	return &Window{
		ttl:   ttl,
		nowFn: time.Now,
		// Ленивая инициализация map: создаём только при первом использовании.
		// Если ttl == 0, map никогда не понадобится.
		entries: nil,
	}
}

// Contains сообщает, находится ли key в окне и не истёк ли его TTL.
// Чистый lookup: НЕ модифицирует состояние окна, идемпотентен.
//
// Семантика:
//   - (nil) → false, без паники
//   - ttl == 0 → false (dedup выключен)
//   - ключ есть и не истёк → true
//   - ключ есть и истёк → false (запись НЕ удаляется и НЕ обновляется;
//     это сделает следующий Mark, чтобы не платить cleanup-стоимость
//     на каждом Contains)
//   - ключа нет → false
func (w *Window) Contains(key string) bool {
	// nil-safe: пустой receiver не паникует, а молча "пропускает".
	// Это упрощает executor-ы, которым не нужно проверять инициализацию.
	if w == nil {
		return false
	}

	// Dedup отключён конфигурацией. Не лезем в map без необходимости.
	if w.ttl == 0 {
		return false
	}

	// Ленивая инициализация map ровно перед первым использованием.
	// Сюда попадаем только если ttl > 0.
	w.mu.Lock()
	defer w.mu.Unlock()

	// Повторная проверка под локом — могло быть nil до вызова mu.Lock.
	if w.entries == nil {
		return false
	}

	now := w.nowFn()
	existing, ok := w.entries[key]
	if !ok {
		return false
	}

	// Ключ есть в map. Считаем его активным, только если его дедлайн
	// ещё не прошёл. Истёкший ключ treated как отсутствующий,
	// но физически не удаляется — его вычистит ближайший Mark.
	return existing.After(now)
}

// Mark записывает key в окно (или продлевает TTL существующего).
// Side-effect: модифицирует внутреннее состояние. Потокобезопасно.
//
// Семантика:
//   - (nil) → no-op, без паники
//   - ttl == 0 → no-op (dedup выключен)
//   - ключ есть → обновляется дедлайн до now+ttl (sliding window)
//   - ключа нет → создаётся запись с дедлайном now+ttl
//
// O(1) cleanup: при каждом Mark пробегаем по map и удаляем истёкшие
// записи в окрестности. Если их скопилось много, имеет смысл добавить
// фоновый janitor (см. SUGGESTION в DECISIONS).
// Пока это приемлемо для типичных объёмов (тысячи IP).
func (w *Window) Mark(key string) {
	// nil-safe и ttl=0 — оба случая no-op. Симметрично с Contains.
	if w == nil || w.ttl == 0 {
		return
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	// Ленивая инициализация map.
	if w.entries == nil {
		w.entries = make(map[string]time.Time)
	}

	now := w.nowFn()
	w.entries[key] = now.Add(w.ttl)

	// Чистим истёкшие. Можно было бы делать это только при превышении
	// порога размера, но текущая цена O(n) приемлема для типичных
	// объёмов. Это сохраняет Size() точным без отдельной метрики.
	for k, t := range w.entries {
		if !t.After(now) {
			delete(w.entries, k)
		}
	}
}

// IsDuplicate — convenience-обёртка поверх Contains+Mark.
//
// Семантика:
//   - если Contains(key) == true → return true (без Mark)
//   - иначе Mark(key) и return false
//
// Эквивалент: `if w.Contains(key) { return true }; w.Mark(key); return false`.
//
// ВНИМАНИЕ: эта обёртка имеет side-effect (Mark) при первом появлении
// ключа. Для flaky-safe паттерна (Contains до, Mark после успеха)
// используйте Contains и Mark по отдельности, а не эту обёртку.
func (w *Window) IsDuplicate(key string) bool {
	if w.Contains(key) {
		return true
	}
	w.Mark(key)
	return false
}

// Size возвращает текущее число хранимых ключей.
// Полезно для метрик и тестов. Не делаем снимок map: возвращаем
// число "примерно сейчас", читатель сам решает, нужна ли атомарность.
func (w *Window) Size() int {
	if w == nil || w.ttl == 0 {
		return 0
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.entries)
}
