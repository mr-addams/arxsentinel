// ========================== Module: queue/bbolt =================================
//   bbolt-backed persistent queue for bare-metal and Docker-on-host deployments.
//   Events survive process restarts. One .db file per executor instance.
//
//   WHAT IS HERE:
//     BboltQueue — implements Queue via bbolt embedded database
//     NewBboltQueue — open or create .db file, initialize bucket
//
//   CONCURRENCY:
//     Write-goroutine pattern: single background writer owns all bbolt write
//     transactions. Push sends to writes channel; Pop polls in read-only tx.
//     This is idiomatic Go for single-writer resources, not a workaround.
//
//   BUCKET LAYOUT:
//     Bucket "q": "\x00seq" (next write key), "\x00read" (next read key),
//     uint64 big-endian keys → JSON ThreatEvent values.
// ================================================================================

package queue

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/mr-addams/arxsentinel/pkg/plugin"
	"go.etcd.io/bbolt"
)

var (
	// ErrQueueCorrupted is returned when the bbolt queue contains malformed data.
	ErrQueueCorrupted = errors.New("queue: bbolt queue data corrupted")
)

// opKind distinguishes write operations sent to the background goroutine.
type opKind int

const (
	opPush    opKind = iota // write a new event
	opDelete                // delete the current read key and advance the read pointer
)

// writeOp carries a single write request to the background write goroutine.
type writeOp struct {
	kind   opKind
	event  plugin.ThreatEvent
	result chan error
}

// BboltQueue implements Queue using an embedded bbolt database.
// All bbolt write transactions are serialised through a single background
// goroutine. Read transactions are performed directly on Pop.
type BboltQueue struct {
	db     *bbolt.DB
	bucket []byte
	writes chan writeOp
	done   chan struct{}
	once   sync.Once
	wg     sync.WaitGroup
}

// NewBboltQueue opens or creates a bbolt database at path and initialises
// the queue bucket. If the bucket already exists, its seq and read counters
// are preserved. Returns an error if the database cannot be opened.
func NewBboltQueue(path string, bucket string) (*BboltQueue, error) {
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

	q := &BboltQueue{
		db:     db,
		bucket: bname,
		// writes is buffered to allow Push to queue without blocking during event bursts.
		// Buffer of 64 covers typical threat batch sizes without excessive memory use.
		writes: make(chan writeOp, 64),
		done:   make(chan struct{}),
	}

	q.wg.Add(1)
	go q.writeLoop()

	return q, nil
}

// writeLoop is the single background goroutine that owns all bbolt write
// transactions. It serialises Push and delete operations, guaranteeing
// that only one Update call is in flight at any time.
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
			var err error
			switch op.kind {
			case opPush:
				err = q.db.Update(func(tx *bbolt.Tx) error {
					return q.writePush(tx, op.event)
				})
			case opDelete:
				err = q.db.Update(func(tx *bbolt.Tx) error {
					return q.writeDeleteAndAdvance(tx)
				})
			}
			op.result <- err
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

	seq++
	binary.BigEndian.PutUint64(seqBytes, seq)
	return b.Put([]byte("\x00seq"), seqBytes)
}

// writeDeleteAndAdvance deletes the current read key and increments the
// read pointer.
func (q *BboltQueue) writeDeleteAndAdvance(tx *bbolt.Tx) error {
	b := tx.Bucket(q.bucket)
	if b == nil {
		return errors.New("queue: bucket not found")
	}

	readBytes := b.Get([]byte("\x00read"))
	if len(readBytes) != 8 {
		return ErrQueueCorrupted
	}
	read := binary.BigEndian.Uint64(readBytes)

	var key [8]byte
	binary.BigEndian.PutUint64(key[:], read)

	if err := b.Delete(key[:]); err != nil {
		return err
	}

	read++
	binary.BigEndian.PutUint64(readBytes, read)
	return b.Put([]byte("\x00read"), readBytes)
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
// the context is cancelled, or the queue is closed. When the queue is empty
// it polls with a 100ms ticker, checking ctx.Done() between attempts.
func (q *BboltQueue) Pop(ctx context.Context) (plugin.ThreatEvent, error) {
	// 100ms poll interval balances responsiveness with CPU usage (per D_Q2).
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-q.done:
			return plugin.ThreatEvent{}, ErrQueueClosed
		case <-ctx.Done():
			return plugin.ThreatEvent{}, ctx.Err()
		default:
		}

		event, found, err := q.tryRead()
		if err != nil {
			return plugin.ThreatEvent{}, err
		}
		if found {
			return event, nil
		}

		select {
		case <-q.done:
			return plugin.ThreatEvent{}, ErrQueueClosed
		case <-ctx.Done():
			return plugin.ThreatEvent{}, ctx.Err()
		case <-ticker.C:
		}
	}
}

// tryRead attempts to read one event from the queue in a read transaction.
// It returns the event and true if found, or false if the queue is empty.
func (q *BboltQueue) tryRead() (plugin.ThreatEvent, bool, error) {
	var event plugin.ThreatEvent
	var found bool

	err := q.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket(q.bucket)
		if b == nil {
			return errors.New("queue: bucket not found")
		}

		readBytes := b.Get([]byte("\x00read"))
		if len(readBytes) != 8 {
			return ErrQueueCorrupted
		}
		read := binary.BigEndian.Uint64(readBytes)

		var key [8]byte
		binary.BigEndian.PutUint64(key[:], read)

		data := b.Get(key[:])
		if data == nil {
			return nil
		}

		if err := json.Unmarshal(data, &event); err != nil {
			return err
		}
		found = true
		return nil
	})
	if err != nil {
		return plugin.ThreatEvent{}, false, err
	}
	if !found {
		return plugin.ThreatEvent{}, false, nil
	}

	// Delete processed key and advance read pointer via the write goroutine.
	err = q.deleteAndAdvance()
	if err != nil {
		return plugin.ThreatEvent{}, false, err
	}

	return event, true, nil
}

// deleteAndAdvance sends a delete operation to the write goroutine.
func (q *BboltQueue) deleteAndAdvance() error {
	result := make(chan error, 1)
	op := writeOp{kind: opDelete, result: result}

	select {
	case <-q.done:
		return ErrQueueClosed
	case q.writes <- op:
	}

	// Mirror safeSend: also select on q.done when waiting for result, so Pop
	// does not deadlock if Close fires after the op was enqueued but before
	// writeLoop processes it.
	select {
	case <-q.done:
		return ErrQueueClosed
	case err := <-result:
		return err
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
		return 0
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
