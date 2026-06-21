// ========================== Module: queue/config ================================
//   Configuration types for pluggable queue backends.
//   QueueConfig is embedded in ExecutorSourceRef for per-source queue selection.
// ================================================================================

package queue

// QueueType identifies the queue backend implementation.
type QueueType string

const (
	QueueTypeMemory QueueType = "memory" // in-process buffered channel; events lost on restart
	QueueTypeBbolt  QueueType = "bbolt"  // file-backed persistent queue; suited for bare-metal/Docker
	QueueTypeRedis  QueueType = "redis"  // external Redis list; suited for k8s/multi-replica
)

// QueueConfig specifies the backend and its parameters for a named queue.
// Used in ExecutorSourceRef.Queue. If nil, MemoryQueue with default buffer is used.
type QueueConfig struct {
	Type   QueueType `yaml:"type"`             // YAML: type — backend selector: "memory" | "bbolt" | "redis". Required.
	Path   string    `yaml:"path,omitempty"`   // YAML: path — bbolt: path to .db file (e.g. /data/queue.db). Required for bbolt.
	Bucket string    `yaml:"bucket,omitempty"` // YAML: bucket — bbolt: bucket name. Default: "arxsentinel".
	URL    string    `yaml:"url,omitempty"`    // YAML: url — redis: Redis URL (e.g. redis://localhost:6379). Required for redis.
	Key    string    `yaml:"key,omitempty"`    // YAML: key — redis: Redis list key. Default: "arxsentinel:queue:<executor_name>".
}

func (c QueueConfig) EffectiveBucket() string {
	if c.Bucket != "" {
		return c.Bucket
	}
	return "arxsentinel"
}

func (c QueueConfig) EffectiveKey(name string) string {
	if c.Key != "" {
		return c.Key
	}
	return "arxsentinel:queue:" + name
}

// ExecutorSourceRef — reference to a Named Channel Switch source.
//
// Name is the channel name registered by sentinel-threat sink. Queue is an optional
// per-source queue backend; nil → default MemoryQueue with DefaultBufferSize (legacy
// behaviour, identical to pre-QueueConfig state).
//
// YAML tags match the original form — user configs remain valid without change.
// Type moved to this package per Flow 073 Task 1.3.2.2 (ADR-002 ownership: Executor
// source routing is Core, so the type lives alongside QueueConfig).
type ExecutorSourceRef struct {
	Name  string       `yaml:"name"`            // YAML: channel name registered by sentinel-threat sink
	Queue *QueueConfig `yaml:"queue,omitempty"` // YAML: optional per-source queue backend; nil → default MemoryQueue
}
