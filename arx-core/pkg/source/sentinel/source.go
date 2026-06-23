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
//	Gate B (Flow 083 / Task 3.3 / RESOLVED-D strategy II):
//	  The source no longer JSON-decodes the wire payload into the core
//	  (the product-owned ThreatEvent was migrated out of arx-core into
//	  cmd/arxsentinel/internal/threat/).
//	  Instead the raw queue bytes are wrapped as a json.RawMessage in
//	  Event.Payload — opaque to core, decoded by the product-side
//	  consumer (cmd/arxsentinel/queue_event_source.Pop and the threat
//	  formatter impls). Boundary invariant: arx-core/pkg/source/sentinel
//	  does NOT import cmd/arxsentinel/internal/threat.
//
//	  Wire shape (the JSON object layout emitted by FormatSentinelThreat):
//	  {ts, ip, score, level, modules, reason, source}. Encoded into
//	  json.RawMessage and carried verbatim into Event.Payload; the
//	  envelope (Source / SourceType / Stream / Timestamp) is filled
//	  from queue metadata and observation time. Level on the envelope
//	  is left empty here — the downstream scoring step assigns it later.
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
//   - Полученные JSON-байты оборачиваются как json.RawMessage и несутся в
//     Event.Payload (core остаётся opaque — не type-asserts и не интерпретирует).
//   - Envelope (Source/SourceType/Stream/Timestamp) заполняется из queue-метаданных.
//     Level на envelope оставлен пустым — продуктовый скорер присваивает его
//     после скоринга (RESOLVED-Q1a envelope ownership).
//   - Если `out` полон — event отбрасывается и инкрементируется Dropped.
//
// Gate B (Flow 083 / Task 3.3 / RESOLVED-D): the wire payload is carried
// opaquely as json.RawMessage; the product-side consumer
// (cmd/arxsentinel/queue_event_source.Pop or a threat formatter impl)
// JSON-decodes it into threat.ThreatEvent. Core has no knowledge of the
// payload type (RESOLVED-Q3b — generic payload).
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

		// Gate B: opaque payload (json.RawMessage). The product consumer is
		// responsible for decoding it into threat.ThreatEvent. We only validate
		// that the bytes are valid JSON before passing them through, so a
		// malformed payload does not silently corrupt downstream consumers.
		if !json.Valid(payload) {
			s.parseErrors.Add(1)
			if s.logFn != nil {
				s.logFn("SENTINEL", fmt.Sprintf("invalid JSON payload (%d bytes)", len(payload)), "debug")
			}
			continue
		}

		ev := &plugin.Event{
			Envelope: plugin.Envelope{
				Timestamp:  time.Now().UTC(),
				Source:     "sentinel:" + s.name,
				SourceType: "sentinel",
				Level:      "", // downstream scoring fills later
			},
			Payload: json.RawMessage(payload),
		}

		select {
		case out <- ev:
		default:
			s.dropped.Add(1)
		}
	}
}