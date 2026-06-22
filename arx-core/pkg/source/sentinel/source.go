// ========================== Module pkg/source/sentinel ==================================
//
//	SentinelSource — обратное направление по отношению к pkg/sink/sentinel/:
//	читает ThreatEvent из Named Channel Switch (NCS) через executor.AttachReader
//	и доставляет их в pipeline как LogEntry.
//
//	Архитектурная роль:
//	  pkg/sink/sentinel/   — OUTPUT: pipeline → NCS   (уже есть, не трогаем)
//	  pkg/source/sentinel/ — INPUT : NCS     → pipeline (этот пакет)
//
//	Два плагина разнесены по разным директориям в полном соответствии
//	с source/sink-разделением arxsentinel, но разделяют общий протокол ThreatEvent.
//
//	Use case: один pipeline пишет ThreatEvent в NCS через sentinel-threat sink,
//	другой pipeline читает их из того же NCS через этот sentinel source.
//	Позволяет строить plugin-only цепочки (Pipeline A → NCS → Pipeline B).
//
//	WHAT IS HERE:
//	  - SentinelSource struct — Pop-Loop из NCS → LogEntry → pipeline
//	  - New() / NewWithQueue() — конструкторы (для тестов inject queue.Queue)
//	  - Run() — главный цикл: q.Pop(ctx) → threatToEntry() → non-blocking send
//	  - Name(), Close(), Stats() — Source interface
//
//	WHAT IS NOT HERE:
//	  - Manifest() — вынесен в manifest.go
//	  - init()/registration — вынесено в register.go
//	  - NCS lifecycle (executor.AttachWriter/DetachWriter)
//	  - ThreatEvent serialization (queue хранит их как структуры)
//
//	CONFIGURATION:
//	  cfg.Addr имеет формат "ncs://<queue-name>" — имя зарегистрированной
//	  в NCS очереди. Пустой или невалидный адрес → ошибка в New().
package sentinel

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/mr-addams/arx-core/pkg/executor/queue"
	"github.com/mr-addams/arx-core/pkg/ncs"
	"github.com/mr-addams/arx-core/pkg/plugin"
)

// addrScheme — префикс, выделяющий NCS-адрес из cfg.Addr.
// Помогает отличать sentinel source от других source-плагинов и валидировать конфиг на старте.
const addrScheme = "ncs://"

// SentinelSource читает ThreatEvent из NCS и доставляет их как *LogEntry в pipeline.
//
// Жизненный цикл:
//  1. main.go (или pipeline builder) вызывает executor.AttachWriter(name, ...) —
//     pipeline-sink регистрирует очередь в NCS ДО запуска источника.
//  2. New() / NewWithQueue() вызывает executor.AttachReader(name) —
//     получает Queue.Queue для чтения.
//  3. Run() крутит Pop(ctx) в цикле, пока ctx не отменён или очередь не закрыта.
//  4. Close() — no-op: queue lifecycle принадлежит sink/writer'у.
type SentinelSource struct {
	name  string      // имя очереди в NCS (без схемы); из cfg.Addr
	q     queue.Queue // handle для Pop(ctx); shared с sink/writer'ом
	logFn func(tag, msg, level string)

	linesRead   atomic.Int64 // всего ThreatEvent получено из очереди
	parseErrors atomic.Int64 // ThreatEvent с пустым IP (невалидные для pipeline)
	dropped     atomic.Int64 // entries отброшены из-за полного downstream-канала
}

// New создаёт SentinelSource и регистрирует его в NCS как reader.
// addr имеет формат "ncs://<queue-name>" — должен совпадать с именем в executor.AttachWriter.
// logFn может быть nil.
//
// Called from: pkg/source registry (init() → Build).
// Non-blocking — возвращает сразу после AttachReader. Если очередь с таким именем
// ещё не зарегистрирована, AttachReader вернёт ошибку — pipeline упадёт на старте.
func New(addr string, logFn func(tag, msg, level string)) (*SentinelSource, error) {
	name, err := parseAddr(addr)
	if err != nil {
		return nil, fmt.Errorf("sentinel source: %w", err)
	}
	q, err := ncs.AttachReader(name)
	if err != nil {
		return nil, fmt.Errorf("sentinel source %q: %w", name, err)
	}
	return newWithQueue(name, q, logFn), nil
}

// NewWithQueue — конструктор с явной инъекцией Queue.
// Используется в unit-тестах, чтобы не зависеть от global NCS singleton.
// В production вызывается New() — он сам делает AttachReader.
func NewWithQueue(name string, q queue.Queue, logFn func(tag, msg, level string)) *SentinelSource {
	return newWithQueue(name, q, logFn)
}

// newWithQueue — общая инициализация полей после валидации.
func newWithQueue(name string, q queue.Queue, logFn func(tag, msg, level string)) *SentinelSource {
	return &SentinelSource{
		name:  name,
		q:     q,
		logFn: logFn,
	}
}

// parseAddr разбирает "ncs://<queue-name>" на scheme и name.
// Пустое имя или неверная схема — ошибка (fail-fast на старте).
func parseAddr(addr string) (name string, err error) {
	if !strings.HasPrefix(addr, addrScheme) {
		return "", fmt.Errorf("invalid sentinel address %q: expected %q scheme", addr, addrScheme)
	}
	name = strings.TrimPrefix(addr, addrScheme)
	if name == "" {
		return "", fmt.Errorf("invalid sentinel address %q: queue name is empty", addr)
	}
	return name, nil
}

// Name возвращает human-readable идентификатор источника.
func (s *SentinelSource) Name() string { return "sentinel:" + s.name }

// Close — no-op: жизненный цикл очереди принадлежит sink/writer'у (pkg/sink/sentinel/).
// DetachReader не существует — NCS закрывает очередь когда последний writer делает DetachWriter.
func (s *SentinelSource) Close() error { return nil }

// Stats возвращает снимок runtime-счётчиков.
func (s *SentinelSource) Stats() plugin.SourceStats {
	return plugin.SourceStats{
		LinesRead:   s.linesRead.Load(),
		ParseErrors: s.parseErrors.Load(),
		Dropped:     s.dropped.Load(),
	}
}

// Run крутит Pop-цикл до отмены контекста или закрытия очереди.
//
// Поведение:
//   - На каждой итерации делается q.Pop(ctx). Если ctx отменён — выходим с nil.
//   - Если очередь закрыта (ErrQueueClosed) — выходим с nil (нормальный shutdown).
//   - Другие ошибки Pop логируются (если logFn задан) и цикл продолжается.
//   - Полученный ThreatEvent конвертируется в LogEntry и отправляется в `out` неблокирующим send'ом.
//   - Если `out` полон — entry отбрасывается и инкрементируется Dropped.
//
// Конверсия ThreatEvent → LogEntry:
//
//	RemoteAddr = event.IP           (TCP-адрес для downstream pipeline)
//	RealIP     = event.IP           (используется whitelist/whois/checks)
//	ChainIssue = "sentinel:event"   (маркер sentinel-происхождения для pipeline)
//	UserAgent  = event.Reason       (содержит список сработавших модулей и score)
//	Time       = event.Timestamp
//
// drop-policy: non-blocking send с default-веткой → dropped++.
// Это соответствует D3-политике других source-плагинов (syslog, stdin).
func (s *SentinelSource) Run(ctx context.Context, out chan<- *plugin.LogEntry) error {
	for {
		event, err := s.q.Pop(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				// ctx отменён — корректный shutdown, без ошибки.
				return nil
			}
			if errors.Is(err, queue.ErrQueueClosed) {
				// Очередь закрыта writer'ом (DetachWriter последнего sink'а).
				// Дренаж: если в момент Close в буфере ещё что-то лежало, мы бы это забрали
				// в предыдущих итерациях. Здесь очередь гарантированно пуста — выходим.
				return nil
			}
			// Прочие ошибки (сетевые, I/O) — логируем и делаем паузу перед retry.
			// Пауза предотвращает busy-loop при персистентной ошибке (I/O, corruption).
			if s.logFn != nil {
				s.logFn("SENTINEL", fmt.Sprintf("queue.Pop error: %v", err), "error")
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}

		s.linesRead.Add(1)
		entry := threatToEntry(event)
		if entry == nil {
			// event без IP — pipeline не сможет сматчить с правилами.
			// Считаем parse error и пропускаем.
			s.parseErrors.Add(1)
			if s.logFn != nil {
				s.logFn("SENTINEL", "dropping threat event with empty IP", "debug")
			}
			continue
		}

		select {
		case out <- entry:
		default:
			// Downstream переполнен — отбрасываем и инкрементируем счётчик.
			s.dropped.Add(1)
		}
	}
}

// threatToEntry конвертирует ThreatEvent в LogEntry для pipeline.
// Возвращает nil если event.IP пустой — pipeline не сможет сматчить с правилами.
//
// Поля LogEntry, заполняемые из ThreatEvent:
//   - Time:       event.Timestamp
//   - RemoteAddr: event.IP
//   - RealIP:     event.IP
//   - UserAgent:  event.Reason (содержит "modules:score" — полезно для дебага)
//   - ChainIssue: "sentinel:event" (маркер sentinel-происхождения)
//
// Остальные поля оставлены пустыми — sentinel-threat не несёт HTTP-метод/URI/Status.
func threatToEntry(event plugin.ThreatEvent) *plugin.LogEntry {
	if event.IP == "" {
		return nil
	}
	return &plugin.LogEntry{
		Time:       event.Timestamp,
		RemoteAddr: event.IP,
		RealIP:     event.IP,
		UserAgent:  event.Reason,
		ChainIssue: "sentinel:event",
	}
}
