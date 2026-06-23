// ========================== Executors — top-level autonomous goroutines ==================
//   Named Channel Switch (NCS) based dispatch (Flow #042).
//
//   ЧТО ЗДЕСЬ:
//     - preRegisterExecutorQueues()     — пре-регистрация NCS-очередей executor'ов
//     - collectSentinelSinkNames()      — собирает имена sentinel-threat выходов из конфига
//     - sortedKeys()                    — стабильный порядок ключей для error-сообщений
//     - startExecutors()                — top-level автономные горутины

package main

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/mr-addams/arx-core/pkg/executor/queue"
	"github.com/mr-addams/arxsentinel/internal/sys/config"
	"github.com/mr-addams/arxsentinel/internal/sys/utils"
	pkgexecutor "github.com/mr-addams/arx-core/pkg/executor"
	ncs "github.com/mr-addams/arx-core/pkg/ncs"
	"github.com/mr-addams/arx-core/pkg/plugin"
)

// productQueueNamespace — product-owned default for bbolt bucket and redis key prefix.
// Core (arx-core/pkg/executor/queue) has no hardcoded default; the product is the only
// legitimate owner of its own namespace. Phase 5 (Flow 083).
const productQueueNamespace = "arxsentinel"

// preRegisterExecutorQueues pre-registers each executor source that has a queue:
// section with its declared backend (bbolt/redis) and verifies that every
// pre-registered name is referenced by at least one sentinel-threat output in
// the pipeline.
//
// Without the wiring check, a typo in an executor source name silently creates
// a pre-registered backend queue (never written to) while the sink creates a
// fresh MemoryQueue on first AttachWriter. Events then flow into memory
// instead of the intended bbolt/redis backend, with no error surfaced. This
// function returns a fail-fast error in that case.
//
// Sources without queue: are skipped (legacy MemoryQueue path inside the sink
// cannot drift from the executor's source list).
//
// Other failure modes also return errors: bbolt file open failure, unreachable
// Redis, unknown queue type. All are configuration errors that should abort
// startup rather than silently degrade.
//
// IMPORTANT: validation runs FIRST and must complete cleanly across the whole
// config before any RegisterSinkFromConfig call touches the Named Channel
// Switch. Otherwise a partial registration (one source OK, the next missing
// its sink) would leave an orphan bbolt/redis queue sitting in hubQueues with
// no way to clean it up — the operator would have to restart the process to
// free it.
func preRegisterExecutorQueues(cfg *config.Config) error {
	available := collectSentinelSinkNames(cfg)

	// Phase 1: wiring check. Read-only — no side effects on the channel switch.
	for _, ec := range cfg.Executors {
		for _, src := range ec.Sources {
			if src.Queue == nil {
				continue
			}
			if _, ok := available[src.Name]; !ok {
				return fmt.Errorf(
					"executor %q source %q (queue=%s) is not referenced by any sentinel-threat output; "+
						"available sink names: [%s]",
					ec.Name, src.Name, src.Queue.Type, strings.Join(sortedKeys(available), ", "),
				)
			}
		}
	}

	// Phase 2: registration. Only reached when every queue: section matches an
	// existing sentinel-threat output, so hubQueues is consistent post-call.
	for _, ec := range cfg.Executors {
		for _, src := range ec.Sources {
			if src.Queue == nil {
				continue
			}
			// Phase 5 (Flow 083): core dropped hardcoded defaults; product applies its own
			// namespace explicitly so cf/ros-ban and other queue-backed executors still
			// receive events. Without this, EffectiveBucket/EffectiveKey would panic at
			// RegisterSinkFromConfig. Core has no knowledge of this constant.
			if src.Queue.Type == queue.QueueTypeBbolt && src.Queue.Bucket == "" {
				copy := *src.Queue
				copy.Bucket = productQueueNamespace
				src.Queue = &copy
			}
			if src.Queue.Type == queue.QueueTypeRedis && src.Queue.Key == "" {
				copy := *src.Queue
				copy.Key = productQueueNamespace + ":queue:" + src.Name
				src.Queue = &copy
			}
			if err := ncs.RegisterSinkFromConfig(src.Name, src.Queue, utils.AsLogger()); err != nil {
				return fmt.Errorf("executor %q source %q: %w", ec.Name, src.Name, err)
			}
		}
	}
	return nil
}

// collectSentinelSinkNames returns the set of channel names declared by
// sentinel-threat outputs in any of the three config locations (top-level,
// per-stream, per-pipeline). Non-sentinel-threat outputs and empty names are
// ignored — the sentinel sink rejects empty names at construction time.
func collectSentinelSinkNames(cfg *config.Config) map[string]struct{} {
	set := make(map[string]struct{})
	add := func(outputs []config.SinkConfig) {
		for _, out := range outputs {
			if out.Type != "sentinel-threat" || out.Name == "" {
				continue
			}
			set[out.Name] = struct{}{}
		}
	}
	add(cfg.Outputs)
	for _, s := range cfg.Streams {
		add(s.Outputs)
		for _, p := range s.Pipelines {
			add(p.Outputs)
		}
	}
	return set
}

// sortedKeys returns the keys of m in deterministic order. Used for stable
// error messages.
func sortedKeys(m map[string]struct{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// startExecutors builds all top-level executors from config and launches them as goroutines.
// Called from: main.
// Non-blocking.
//
// Each executor connects to Named Channel Switch sources and runs until ctx is cancelled
// or the source channel is closed. Must be called after all NCS sinks are registered.
//
// Returns an error if any executor cannot be built or any named source cannot be found.
// On error, the caller should log and continue — executor startup failure is not fatal
// for the rest of the pipeline (streams still process logs).
//
// Flow 073 / Task 1.3.1 — F1 closure: utils.AsLogger() is passed into Build() so
// the executor factory receives a real bridge instead of logger.Nop. The
// pre-1.3.1 wiring had no logger argument at this layer; this is the cmd-side
// counterpart of the registry signature change. EXECUTOR-tag diagnostics
// (find/create list, sync errors, reload errors, sweep failures) become
// observable in production output — see integration diff expected: +EXECUTOR log lines.
func startExecutors(ctx context.Context, cfg *config.Config, wg *sync.WaitGroup) error {
	for _, ec := range cfg.Executors {
		ex, err := pkgexecutor.Build(pkgexecutor.ExecutorConfig{
			Name:   ec.Name,
			Type:   ec.Type,
			Config: ec.Config,
		}, utils.AsLogger())
		if err != nil {
			return fmt.Errorf("executor %q: build: %w", ec.Name, err)
		}

		for _, src := range ec.Sources {
			q, err := ncs.AttachReader(src.Name)
			if err != nil {
				return fmt.Errorf("executor %q: source %q: %w", ec.Name, src.Name, err)
			}

			// Phase 2.2 (Flow 083 / Gate A — RESOLVED-D strategy II / OPEN-Q3b gray zone):
			// queue.Queue operates on opaque []byte payloads (see
			// pkg/executor/queue/queue.go) — the wire format is owned by the
			// sink-side Formatter and the executor-side adapter. Until the
			// proper adapter lands in Task 3.3, wrap the queue with a bytes→Event
			// translator that JSON-decodes the payload into a generic
			// *plugin.Event. Executors type-assert Event.Payload to their
			// product-owned type (Gate A: *plugin.ThreatEvent) inside Run.
			source := newQueueEventSource(q)

			wg.Add(1)
			go func(ex plugin.Executor, src plugin.EventSource) {
				defer wg.Done()
				if err := ex.Run(ctx, src); err != nil && err != context.Canceled {
					utils.Log("EXECUTOR", fmt.Sprintf("executor %s: %v", ex.Name(), err), "error")
				}
			}(ex, source)
		}
	}
	return nil
}
