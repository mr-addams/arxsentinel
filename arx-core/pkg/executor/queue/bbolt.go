// ========================== Module: queue/bbolt =================================
//   bbolt-backed persistent queue for bare-metal and Docker-on-host deployments.
//   Events survive process restarts. One .db file per executor instance.
//
//   WHAT IS HERE:
//     BboltQueue — implements Queue via bbolt embedded database
//     NewBboltQueue — open or create .db file, initialize bucket
//
//   CONCURRENCY:
//     Single-writer pattern: все bbolt-транзакции (Push, claim) сериализуются
//     через одну фоновую горутину. Pop отправляет opPopAndAdvance в канал
//     writes; writeLoop выполняет read+delete+advance в одной db.Update,
//     гарантируя, что каждое событие доставляется ровно одному Pop'еру.
//     Push идёт через тот же канал (opPush) на запись.
// ================================================================================

package queue

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/mr-addams/arx-core/pkg/logger"
	"github.com/mr-addams/arx-core/pkg/plugin"
	"go.etcd.io/bbolt"
)

var (
	// ErrQueueCorrupted is returned when the bbolt queue contains malformed data.
	ErrQueueCorrupted = errors.New("queue: bbolt queue data corrupted")
)

// opKind distinguishes write operations sent to the background goroutine.
type opKind int

const (
	opPush opKind = iota // write a new event
	// opPopAndAdvance atomically claims the next event: reads it, deletes the
	// key, and advances the read pointer — all in a single db.Update tx.
	// Only one concurrent Pop gets each event; others receive (zero, false, nil)
	// and retry on the next ticker tick.
	opPopAndAdvance
)

// bboltPopPollInterval — интервал опроса пустой bbolt-очереди в Pop.
// 100ms обеспечивает баланс между отзывчивостью и CPU (D_Q2): при поступлении
// нового события Pop заметит его в среднем за ~50ms, и busy-loop не разогревается.
const bboltPopPollInterval = 100 * time.Millisecond

// popResult is the outcome of an opPopAndAdvance claim.
type popResult struct {
	event plugin.ThreatEvent
	found bool
	err   error
}

// writeOp carries a single write request to the background write goroutine.
// result is used by opPush; popResult is used by opPopAndAdvance.
// Exactly one of the two channels is meaningful for a given op.kind.
type writeOp struct {
	kind      opKind
	event     plugin.ThreatEvent
	result    chan error
	popResult chan popResult
}

// BboltQueue implements Queue using an embedded bbolt database.
// All bbolt write transactions (Push, Pop claim) are serialised through a
// single background goroutine, which is the only writer of the underlying
// db. Len() uses a read-only View since it does not mutate state.
type BboltQueue struct {
	db     *bbolt.DB
	bucket []byte
	writes chan writeOp
	done   chan struct{}
	once   sync.Once
	wg     sync.WaitGroup

	// logger is the operational logger injected by the caller. Replaces the
	// pre-1.2 global utils.Log dependency — see Flow 072 Decision 2. Always
	// non-nil in practice (constructor replaces nil with logger.Nop).
	logger logger.Logger
}

// NewBboltQueue opens or creates a bbolt database at path and initialises
// the queue bucket. If the bucket already exists, its seq and read counters
// are preserved. Returns an error if the database cannot be opened.
//
// log is the operational logger used for QUEUE-tag diagnostics. If nil is
// passed, the constructor replaces it with logger.Nop — the queue never
// crashes on a log call (Flow 072 Decision 2).
func NewBboltQueue(path string, bucket string, log logger.Logger) (*BboltQueue, error) {
	db, err := bbolt.Open(path, 0600, nil)
	if err != nil {
		return nil, err
	}

	bname := []byte(bucket)
	err = db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(bname)
		if err != nil {
			return err
		}
		if b.Get([]byte("\x00seq")) == nil {
			var seq [8]byte
			binary.BigEndian.PutUint64(seq[:], 1)
			if err := b.Put([]byte("\x00seq"), seq[:]); err != nil {
				return err
			}
		}
		if b.Get([]byte("\x00read")) == nil {
			var read [8]byte
			binary.BigEndian.PutUint64(read[:], 1)
			if err := b.Put([]byte("\x00read"), read[:]); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, err
	}

	// Inject the operational logger. nil is replaced with logger.Nop so
	// downstream call sites never need to nil-check. See Flow 072 Decision 2.
	if log == nil {
		log = logger.Nop
	}

	q := &BboltQueue{
		db:     db,
		bucket: bname,
		// writes is buffered to allow Push to queue without blocking during event bursts.
		// Buffer of 64 covers typical threat batch sizes without excessive memory use.
		writes: make(chan writeOp, 64),
		done:   make(chan struct{}),
		logger: log,
	}

	q.wg.Add(1)
	go q.writeLoop()

	return q, nil
}

// writeLoop is the single background goroutine that owns all bbolt write
// transactions. It serialises Push, delete, and claim operations, guaranteeing
// that only one Update call is in flight at any time and that concurrent Pop
// callers never receive the same event (the claim is atomic).
//
// Exits when q.done is closed. q.writes is never closed — closing a channel
// that has concurrent senders causes a race; q.done is the sole shutdown signal.
func (q *BboltQueue) writeLoop() {
	defer q.wg.Done()
	for {
		select {
		case <-q.done:
			return
		case op := <-q.writes:
			switch op.kind {
			case opPush:
				err := q.db.Update(func(tx *bbolt.Tx) error {
					return q.writePush(tx, op.event)
				})
				// Неблокирующая запись: получатель (Push) мог уже выйти по
				// ctx/done — иначе Close() зависнет на wg.Wait().
				select {
				case op.result <- err:
				case <-q.done:
				}
			case opPopAndAdvance:
				// Атомарный claim: читаем, удаляем, продвигаем read-указатель
				// в ОДНОЙ db.Update. Только один Pop получает событие.
				var res popResult
				res.err = q.db.Update(func(tx *bbolt.Tx) error {
					event, found, err := q.readAndClaim(tx)
					if err != nil {
						return err
					}
					if !found {
						// Пустая очередь — никаких мутаций, продвижения не было.
						return nil
					}
					res.event = event
					res.found = true
					return nil
				})
				// Неблокирующая запись: получатель мог уже уйти по ctx/done,
				// иначе Close() зависнет на wg.Wait() — writeLoop пишет в
				// resCh, а resCh никто не читает.
				select {
				case op.popResult <- res:
				case <-q.done:
				}
			}
		}
	}
}

// writePush writes a single event at the current seq key and increments seq.
func (q *BboltQueue) writePush(tx *bbolt.Tx, event plugin.ThreatEvent) error {
	b := tx.Bucket(q.bucket)
	if b == nil {
		return errors.New("queue: bucket not found")
	}

	seqBytes := b.Get([]byte("\x00seq"))
	// If counters are missing or corrupted, treat as empty queue.
	// This can happen if the db was initialized externally or is corrupt.
	if len(seqBytes) != 8 {
		return ErrQueueCorrupted
	}
	seq := binary.BigEndian.Uint64(seqBytes)

	data, err := json.Marshal(event)
	if err != nil {
		return err
	}

	var key [8]byte
	binary.BigEndian.PutUint64(key[:], seq)

	if err := b.Put(key[:], data); err != nil {
		return err
	}

	// Use a fresh buffer — b.Get() returns a read-only slice owned by bbolt;
	// writing into it via PutUint64 corrupts bbolt's internal mmap memory.
	var newSeq [8]byte
	binary.BigEndian.PutUint64(newSeq[:], seq+1)
	return b.Put([]byte("\x00seq"), newSeq[:])
}

// readAndClaim — ядро атомарного Pop. Вызывается ТОЛЬКО из writeLoop
// внутри db.Update. Читает событие по текущему read-указателю, удаляет
// ключ и продвигает указатель — всё в одной write-транзакции.
//
// Возвращает (event, true, nil) если событие было, (zero, false, nil)
// если очередь пуста. При corrupted bucket — (zero, false, err).
//
// Вызывающий (writeLoop) обязан проставить res.found=true и res.event
// ТОЛЬКО при err==nil && found==true, чтобы избежать возврата данных
// при ошибке tx.
func (q *BboltQueue) readAndClaim(tx *bbolt.Tx) (plugin.ThreatEvent, bool, error) {
	b := tx.Bucket(q.bucket)
	if b == nil {
		return plugin.ThreatEvent{}, false, errors.New("queue: bucket not found")
	}

	readBytes := b.Get([]byte("\x00read"))
	if len(readBytes) != 8 {
		return plugin.ThreatEvent{}, false, ErrQueueCorrupted
	}
	read := binary.BigEndian.Uint64(readBytes)

	var key [8]byte
	binary.BigEndian.PutUint64(key[:], read)

	data := b.Get(key[:])
	if data == nil {
		// Пустая очередь — нечего удалять, указатель не двигаем.
		return plugin.ThreatEvent{}, false, nil
	}

	var event plugin.ThreatEvent
	if err := json.Unmarshal(data, &event); err != nil {
		return plugin.ThreatEvent{}, false, err
	}

	// Удаляем ключ и продвигаем read-указатель в той же tx — атомарно.
	if err := b.Delete(key[:]); err != nil {
		return plugin.ThreatEvent{}, false, err
	}
	var newRead [8]byte
	binary.BigEndian.PutUint64(newRead[:], read+1)
	if err := b.Put([]byte("\x00read"), newRead[:]); err != nil {
		return plugin.ThreatEvent{}, false, err
	}

	return event, true, nil
}

// Push enqueues a ThreatEvent into the bbolt queue. It sends the event to
// the background write goroutine and waits for the transaction to complete.
// Returns ErrQueueClosed if the queue has been closed.
func (q *BboltQueue) Push(ctx context.Context, event plugin.ThreatEvent) error {
	select {
	case <-q.done:
		return ErrQueueClosed
	default:
	}
	return q.safeSend(ctx, event)
}

// safeSend sends a push writeOp to the write goroutine and waits for the result.
// Both selects include q.done so Push exits cleanly during shutdown.
func (q *BboltQueue) safeSend(ctx context.Context, event plugin.ThreatEvent) error {
	result := make(chan error, 1)
	select {
	case <-q.done:
		return ErrQueueClosed
	case <-ctx.Done():
		return ctx.Err()
	case q.writes <- writeOp{kind: opPush, event: event, result: result}:
	}
	select {
	case <-q.done:
		return ErrQueueClosed
	case <-ctx.Done():
		return ctx.Err()
	case err := <-result:
		return err
	}
}

// Pop dequeues the next ThreatEvent. It blocks until an event is available,
// the context is cancelled, or the queue is closed.
//
// Implementation: atomic claim via writeLoop. Pop sends opPopAndAdvance
// to writes; writeLoop does read+delete+advance in ONE db.Update — this
// guarantees concurrent Poppers never receive the same event. When the
// queue is empty, Pop waits 100ms and retries (ticker pattern for
// responsiveness without a busy-loop).
func (q *BboltQueue) Pop(ctx context.Context) (plugin.ThreatEvent, error) {
	ticker := time.NewTicker(bboltPopPollInterval)
	defer ticker.Stop()

	for {
		// Проверяем ctx/done перед каждым claim — иначе можем зависнуть
		// в ожидании result после того как Close() уже отработал.
		select {
		case <-q.done:
			return plugin.ThreatEvent{}, ErrQueueClosed
		case <-ctx.Done():
			return plugin.ThreatEvent{}, ctx.Err()
		default:
		}

		event, found, err := q.claimOnce(ctx)
		if err != nil {
			return plugin.ThreatEvent{}, err
		}
		if found {
			return event, nil
		}

		// Очередь пуста — ждём либо нового Push (ticker), либо ctx/done.
		select {
		case <-q.done:
			return plugin.ThreatEvent{}, ErrQueueClosed
		case <-ctx.Done():
			return plugin.ThreatEvent{}, ctx.Err()
		case <-ticker.C:
		}
	}
}

// claimOnce sends opPopAndAdvance to writeLoop and waits for the atomic
// result. Returns (event, true, nil) if an event was found, (zero, false,
// nil) if the queue is empty.
//
// ctx cancellation is only honoured BEFORE the op is sent (step 1).
// Once the op is in the writes channel (step 2), we must wait for the
// result without a ctx escape: writeLoop will atomically claim the event
// and send the result to resCh. If we leave step 2 early (e.g. ctx
// expires), the event is permanently lost from the queue — the advance
// already happened inside db.Update. q.done is the only escape in step 2.
func (q *BboltQueue) claimOnce(ctx context.Context) (plugin.ThreatEvent, bool, error) {
	resCh := make(chan popResult, 1)
	op := writeOp{kind: opPopAndAdvance, popResult: resCh}

	// Step 1: send op — bail if ctx is done before we even queue the request.
	select {
	case <-q.done:
		return plugin.ThreatEvent{}, false, ErrQueueClosed
	case <-ctx.Done():
		return plugin.ThreatEvent{}, false, ctx.Err()
	case q.writes <- op:
	}

	// Step 2: wait for result — NO ctx escape here.
	// The op is already in flight; cancelling now would silently lose the event.
	select {
	case <-q.done:
		// Queue is shutting down. Drain resCh opportunistically — writeLoop
		// may have already sent the result before closing q.done.
		select {
		case res := <-resCh:
			return res.event, res.found, res.err
		default:
			// C2: event lost — writeLoop already executed read+delete+advance inside
			// db.Update, but claimOnce was interrupted by Close before receiving the
			// result. Re-queue is not feasible without rewriting bbolt write-loop
			// (see DECISIONS.md D7); log for monitoring instead.
			q.logger.Log("QUEUE", "event lost during shutdown (claim interrupted by Close)", logger.LevelWarning)
			return plugin.ThreatEvent{}, false, ErrQueueClosed
		}
	case res := <-resCh:
		if res.err != nil {
			return plugin.ThreatEvent{}, false, res.err
		}
		return res.event, res.found, nil
	}
}

// Len returns the number of pending events in the queue by subtracting
// the read pointer from the write sequence counter.
func (q *BboltQueue) Len() int {
	var seq, read uint64

	err := q.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(q.bucket)
		if b == nil {
			return errors.New("queue: bucket not found")
		}

		seqBytes := b.Get([]byte("\x00seq"))
		if len(seqBytes) == 8 {
			seq = binary.BigEndian.Uint64(seqBytes)
		}

		readBytes := b.Get([]byte("\x00read"))
		if len(readBytes) == 8 {
			read = binary.BigEndian.Uint64(readBytes)
		}

		return nil
	})
	if err != nil {
		// -1 signals an error — do not confuse with 0 (empty queue).
		// The caller checks < 0 to detect corruption / I/O error.
		return -1
	}

	if seq < read {
		return 0
	}
	return int(seq - read)
}

// Close shuts down the write goroutine and closes the bbolt database.
// It is idempotent — calling Close multiple times is safe.
//
// q.writes is intentionally never closed. Closing it while concurrent Push
// goroutines hold a send reference causes a data race. q.done is the sole
// shutdown signal; writeLoop exits when q.done is closed.
func (q *BboltQueue) Close() error {
	q.once.Do(func() {
		close(q.done) // signals writeLoop, Pop, and in-flight Push to exit
		q.wg.Wait()   // wait for writeLoop to finish before closing db
		q.db.Close()
	})
	return nil
}
