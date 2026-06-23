// ========================== Module: queue/bbolt =================================
//   bbolt-backed persistent queue for bare-metal and Docker-on-host deployments.
//   Events survive process restarts. One .db file per executor instance.
//
//   WHAT IS HERE:
//     BboltQueue — implements Queue via bbolt embedded database
//     NewBboltQueue — open or create .db file, initialize bucket
//
//   CONCURRENCY:
//     Single-writer pattern: all bbolt transactions (Push, claim) are serialised
//     through one background goroutine. Pop sends opPopAndAdvance to writes;
//     writeLoop performs read+delete+advance in one db.Update, guaranteeing
//     that every event is delivered to exactly one Poper.
//     Push uses the same channel (opPush) for writes.
//
//   Phase 2.2: payload is opaque []byte (serialized event). JSON wire form is
//   used by product formatters; bbolt stores the bytes verbatim without any
//   decoding on the queue side.
// ================================================================================

package queue

import (
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"time"

	"github.com/mr-addams/arx-core/pkg/logger"
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
	// Only one concurrent Pop gets each event; others receive (nil, false, nil)
	// and retry on the next ticker tick.
	opPopAndAdvance
)

// bboltPopPollInterval — interval for polling empty bbolt queue in Pop.
// 100ms balances responsiveness and CPU.
const bboltPopPollInterval = 100 * time.Millisecond

// popResult is the outcome of an opPopAndAdvance claim.
type popResult struct {
	payload []byte
	found   bool
	err     error
}

// writeOp carries a single write request to the background write goroutine.
// result is used by opPush; popResult is used by opPopAndAdvance.
// Exactly one of the two channels is meaningful for a given op.kind.
type writeOp struct {
	kind      opKind
	payload   []byte
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

	if log == nil {
		log = logger.Nop
	}

	q := &BboltQueue{
		db:     db,
		bucket: bname,
		writes: make(chan writeOp, 64),
		done:   make(chan struct{}),
		logger: log,
	}

	q.wg.Add(1)
	go q.writeLoop()

	return q, nil
}

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
					return q.writePush(tx, op.payload)
				})
				select {
				case op.result <- err:
				case <-q.done:
				}
			case opPopAndAdvance:
				var res popResult
				res.err = q.db.Update(func(tx *bbolt.Tx) error {
					payload, found, err := q.readAndClaim(tx)
					if err != nil {
						return err
					}
					if !found {
						return nil
					}
					res.payload = payload
					res.found = true
					return nil
				})
				select {
				case op.popResult <- res:
				case <-q.done:
				}
			}
		}
	}
}

func (q *BboltQueue) writePush(tx *bbolt.Tx, payload []byte) error {
	b := tx.Bucket(q.bucket)
	if b == nil {
		return errors.New("queue: bucket not found")
	}

	seqBytes := b.Get([]byte("\x00seq"))
	if len(seqBytes) != 8 {
		return ErrQueueCorrupted
	}
	seq := binary.BigEndian.Uint64(seqBytes)

	var key [8]byte
	binary.BigEndian.PutUint64(key[:], seq)

	if err := b.Put(key[:], payload); err != nil {
		return err
	}

	var newSeq [8]byte
	binary.BigEndian.PutUint64(newSeq[:], seq+1)
	return b.Put([]byte("\x00seq"), newSeq[:])
}

func (q *BboltQueue) readAndClaim(tx *bbolt.Tx) ([]byte, bool, error) {
	b := tx.Bucket(q.bucket)
	if b == nil {
		return nil, false, errors.New("queue: bucket not found")
	}

	readBytes := b.Get([]byte("\x00read"))
	if len(readBytes) != 8 {
		return nil, false, ErrQueueCorrupted
	}
	read := binary.BigEndian.Uint64(readBytes)

	var key [8]byte
	binary.BigEndian.PutUint64(key[:], read)

	data := b.Get(key[:])
	if data == nil {
		return nil, false, nil
	}

	if err := b.Delete(key[:]); err != nil {
		return nil, false, err
	}
	var newRead [8]byte
	binary.BigEndian.PutUint64(newRead[:], read+1)
	if err := b.Put([]byte("\x00read"), newRead[:]); err != nil {
		return nil, false, err
	}

	return data, true, nil
}

// Push enqueues a payload (opaque bytes) into the bbolt queue.
func (q *BboltQueue) Push(ctx context.Context, payload []byte) error {
	select {
	case <-q.done:
		return ErrQueueClosed
	default:
	}
	return q.safeSend(ctx, payload)
}

func (q *BboltQueue) safeSend(ctx context.Context, payload []byte) error {
	result := make(chan error, 1)
	select {
	case <-q.done:
		return ErrQueueClosed
	case <-ctx.Done():
		return ctx.Err()
	case q.writes <- writeOp{kind: opPush, payload: payload, result: result}:
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

// Pop dequeues the next payload.
func (q *BboltQueue) Pop(ctx context.Context) ([]byte, error) {
	ticker := time.NewTicker(bboltPopPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-q.done:
			return nil, ErrQueueClosed
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		payload, found, err := q.claimOnce(ctx)
		if err != nil {
			return nil, err
		}
		if found {
			return payload, nil
		}

		select {
		case <-q.done:
			return nil, ErrQueueClosed
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

func (q *BboltQueue) claimOnce(ctx context.Context) ([]byte, bool, error) {
	resCh := make(chan popResult, 1)
	op := writeOp{kind: opPopAndAdvance, popResult: resCh}

	select {
	case <-q.done:
		return nil, false, ErrQueueClosed
	case <-ctx.Done():
		return nil, false, ctx.Err()
	case q.writes <- op:
	}

	select {
	case <-q.done:
		select {
		case res := <-resCh:
			return res.payload, res.found, res.err
		default:
			q.logger.Log("QUEUE", "event lost during shutdown (claim interrupted by Close)", logger.LevelWarning)
			return nil, false, ErrQueueClosed
		}
	case res := <-resCh:
		if res.err != nil {
			return nil, false, res.err
		}
		return res.payload, res.found, nil
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
		return -1
	}

	if seq < read {
		return 0
	}
	return int(seq - read)
}

// Close shuts down the write goroutine and closes the bbolt database.
// Idempotent — calling Close multiple times is safe.
func (q *BboltQueue) Close() error {
	q.once.Do(func() {
		close(q.done)
		q.wg.Wait()
		q.db.Close()
	})
	return nil
}