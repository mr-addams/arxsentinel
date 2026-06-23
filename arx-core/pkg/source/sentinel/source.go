// ========================== Module pkg/source/sentinel ==================================
//
//	SentinelSource — обратное направление по отношению к pkg/sink/sentinel/:
//	читает ThreatEvent (JSON-encoded) из Named Channel Switch (NCS) через
//	executor.AttachReader и доставляет их в pipeline как *plugin.Event.
//
//	Архитектурная роль:
//	  pkg/sink/sentinel/   — OUTPUT: pipeline → NCS   (уже есть, не трогаем)
//	  pkg/source/sentinel/ — INPUT : NCS     → pipeline (этот пакет)
//
//	Два плагина разнесены по разным директориям в полном соответствии
//	с source/sink-разделением arxsentinel, но разделяют общий протокол —
//	JSON-encoded ThreatEvent bytes, opaque to core.
//
//	Use case: один pipeline пишет события в NCS через sentinel-threat sink,
//	другой pipeline читает их из того же NCS через этот sentinel source.
//	Позволяет строить plugin-only цепочки (Pipeline A → NCS → Pipeline B).
//
//	WHAT IS HERE:
//	  - SentinelSource struct — Pop-Loop из NCS → ThreatEvent → *plugin.Event → pipeline
//	  - New() / NewWithQueue() — конструкторы (для тестов inject queue.Queue)
//	  - Run() — главный цикл: q.Pop(ctx) → JSON-decode → non-blocking send
//	  - Name(), Close(), Stats() — Source interface
//
//	WHAT IS NOT HERE:
//	  - Manifest() — вынесен в manifest.go
//	  - init()/registration — вынесено в register.go
//	  - NCS lifecycle (executor.AttachWriter/DetachReader)
//	  - ThreatEvent serialization (FormatSentinelThreat in cmd/arxsentinel/internal/threat/format)
//
//	CONFIGURATION:
//	  cfg.Addr имеет формата "ncs://<queue-name>" — имя зарегистрированной
//	  в NCS очереди. Пустой или невалидный адрес → ошибка в New().
//
//	Phase 2.2 (Flow 083 / RESOLVED-Q9 / RESOLVED-Q3b):
//	  - NCS payload is opaque []byte (Phase 2.2 generalisation). This source
//	    JSON-decodes the bytes back into a product-owned ThreatEvent, then
//	    wraps it as *plugin.Event{Envelope, Payload}. The envelope fields
//	    that this source can fill at construction time are Source, SourceType,
//	    Stream, Timestamp; Level is left empty (scorer fills it later).
package sentinel

import (
	"context"
	"encoding/json"
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
const addrScheme = "ncs://"

// SentinelSource читает JSON-encoded ThreatEvent из NCS и доставляет их как
// *plugin.Event в pipeline.
//
// Жизненный цикл:
//  1. main.go (или pipeline builder) вызывает executor.AttachWriter(name, ...) —
//     pipeline-sink регистрирует очередь в NCS ДО запуска источника.
//  2. New() / NewWithQueue() вызывает executor.AttachReader(name) —
//     получает Queue.Queue для чтения.
//  3. Run() крутит Pop(ctx) в цикле, пока ctx не отменён или очередь не закрыта.
//  4. Close() — no-op: queue lifecycle принадлежит sink/writer'у.
type SentinelSource struct {
	name  string
	q     queue.Queue
	logFn func(tag, msg, level string)

	linesRead   atomic.Int64
	parseErrors atomic.Int64
	dropped     atomic.Int64
}

// New создаёт SentinelSource и регистрирует его в NCS как reader.
// addr имеет формат "ncs://<queue-name>" — должен совпадать с именем в executor.AttachWriter.
// logFn может быть nil.
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
// Используется в unit-тестах.
func NewWithQueue(name string, q queue.Queue, logFn func(tag, msg, level string)) *SentinelSource {
	return newWithQueue(name, q, logFn)
}

func newWithQueue(name string, q queue.Queue, logFn func(tag, msg, level string)) *SentinelSource {
	return &SentinelSource{
		name:  name,
		q:     q,
		logFn: logFn,
	}
}

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

func (s *SentinelSource) Name() string { return "sentinel:" + s.name }

func (s *SentinelSource) Close() error { return nil }

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
//   - Если очередь закрыта (ErrQueueClosed) — выходим с nil.
//   - Другие ошибки Pop логируются (если logFn задан) и цикл продолжается.
//   - Полученные JSON-байты декодируются в ThreatEvent (canonical product type),
//     оборачиваются в *plugin.Event и отправляются в `out` неблокирующим send'ом.
//   - Если `out` полон — event отбрасывается и инкрементируется Dropped.
//
// Phase 2.2: payload is *plugin.Event (envelope + opaque ThreatEvent payload).
// Level on the envelope is left empty here — the product scorer assigns it
// later. Source/SourceType/Stream/Timestamp are filled from the queue name
// and observation time; they are best-effort transport metadata, not audit-
// quality provenance.
func (s *SentinelSource) Run(ctx context.Context, out chan<- *plugin.Event) error {
	for {
		payload, err := s.q.Pop(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil
			}
			if errors.Is(err, queue.ErrQueueClosed) {
				return nil
			}
			if s.logFn != nil {
				s.logFn("SENTINEL", fmt.Sprintf("queue.Pop error: %v", err), "error")
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}

		s.linesRead.Add(1)

		var event plugin.ThreatEvent
		if jerr := json.Unmarshal(payload, &event); jerr != nil {
			s.parseErrors.Add(1)
			if s.logFn != nil {
				s.logFn("SENTINEL", fmt.Sprintf("decode threat event: %v", jerr), "debug")
			}
			continue
		}

		if event.IP == "" {
			s.parseErrors.Add(1)
			if s.logFn != nil {
				s.logFn("SENTINEL", "dropping threat event with empty IP", "debug")
			}
			continue
		}

		ev := &plugin.Event{
			Envelope: plugin.Envelope{
				Timestamp:  event.Timestamp,
				Source:     "sentinel:" + s.name,
				SourceType: "sentinel",
				Level:      "", // scorer fills later
			},
			Payload: event,
		}

		select {
		case out <- ev:
		default:
			s.dropped.Add(1)
		}
	}
}