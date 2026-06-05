# pkg/sink/exec — Exec Sink

ExecSink delegates threat events to an external plugin binary via subprocess. It fires NDJSON lines over stdin to a managed child process and does not wait for acknowledgement (fire-and-forget). Used when event processing must happen outside the Arxsentinel process — e.g., custom SIEM bridge, legacy pipeline, or external enrichments.

The pipeline calls `Write` for every scored event that reaches the sink stage. The consumer is the external plugin binary spawned at startup; the sink owns the subprocess for its lifetime and shuts it down on `Close`.

## Plugin Identity

| Field | Value |
|-------|-------|
| PluginID | `"exec"` |
| Version | `v1.0.0` |
| Role | `RoleSink` |
| Input | `TypeScoredEvent` |
| Output | `TypeNone` |
| Tags | `["exec", "external", "plugin"]` |

## Module Layout

```
pkg/sink/exec/
├── register.go          # init() registration, factory
```

> Implementation lives in `pkg/execplugin/sink.go`, not in this package.

## Configuration Reference

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `exec` | string | yes | – | Path to the external plugin binary |
| `name` | string | – (auto) | `"exec:<path>"` | Sink name derived from binary path |

Validation: `cfg.Exec != ""` — factory rejects empty exec path.

## Behaviour Details

- **Startup:** `NewSink(execPath)` spawns the plugin binary synchronously via `ManagedProcess`. If spawn fails, constructor returns error.
- **Write:** Fire-and-forget — serializes event as NDJSON `WriteRequest{V: ProtoVersion, Action: "write", Event: threatEventToJSON(event)}` and sends via `proc.Send()`. Mutex-locked through `s.proc.Lock()`.
- **Drop Policy:** No explicit dropped counter; `Dropped` is hardcoded to 0 in `Stats()`.
- **Fire-and-forget rationale (no ACK):** `Write()` does not call `Recv()` after `Send()` — there is no `WriteAck` wait. In `protocol.go:236-237`: *"Absence of ack is not an error — the caller should assume OK if no response is sent."* `WriteAck` is optional (`protocol.go type WriteAck struct`). The sink is intentionally simplified: it does not require a response from the plugin, allowing the plugin to process asynchronously.
- **Behaviour on subprocess crash:** `ManagedProcess.Send()` (`process.go:119`) writes to the `stdin` pipe: `p.stdin.Write(append(line, '\n'))`. If the subprocess has crashed (pipe closed) → `Send()` returns the error `"failed to write to plugin stdin: %w"`. `sink.go Write()` receives the error, increments the `errors` counter, and returns the `error` upstream. **No reconnect is performed** — ExecSink holds a single `ManagedProcess` for its entire lifetime (created in `NewSink`). The only way to recreate it: `Close()` + a fresh `NewSink()` from outside. Comment in `sink.go:26`: *"ExecSink holds a persistent ManagedProcess — recreated only on Close+reopen."*
- **ProtoVersion:** `const ProtoVersion = "1"` (`protocol.go:29`). A string constant used in `WriteRequest.V` for protocol compatibility. Future protocol versions may change this value for backwards-compatibility checks.
- **Error Handling:** Errors during write increment `errors` atomic counter.
- **Protocol:** `WriteRequest` with `ProtoVersion`, action `"write"`, and JSON-serialized event.

## Close / Shutdown

- `Close()` shuts down the subprocess (delegated to `ManagedProcess`).
- No `Reload()` — not needed for external binary.

## Metrics and Stats

| Counter | Type | Description | Incremented When |
|---------|------|-------------|------------------|
| `EventsWritten` | atomic.Int64 | Events sent to subprocess | After each `Write` call |
| `Dropped` | atomic.Int64 | Hardcoded to 0 | Never incremented |
| `Errors` | atomic.Int64 | Write failures | On write error |

## Constructors

```go
func NewSink(execPath string) (*ExecSink, error)
```

## Registration

```go
func init() {
    pkgsink.Register("exec", factory)
    pkgsink.RegisterManifest("exec", manifest)
}
// factory: checks cfg.Exec != "", calls execplugin.NewSink(cfg.Exec)
```

The `init()` function registers both the factory and the manifest with the central `pkgsink` registry. The factory enforces non-empty `cfg.Exec` and delegates construction to `execplugin.NewSink`.

## Quick-Start Example

```yaml
sinks:
  - plugin: exec
    exec: /usr/local/bin/arxsentinel-siem-bridge
```

```bash
# Run the daemon; the exec sink will spawn the plugin binary at startup
arxsentinel --config /etc/arxsentinel/config.yaml
```

## Dependencies

- `pkg/execplugin` — ExecSink implementation, ManagedProcess
- `pkg/plugin` — Manifest, ThreatEvent, SinkStats
- `pkg/sink` — pkgsink register helpers
