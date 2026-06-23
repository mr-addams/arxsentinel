# pkg/sink/exec — Exec Sink

The `exec` sink delivers every scored `*plugin.Event` to an external
plugin binary running as a managed subprocess. The plugin communicates with
arx-core over NDJSON on its stdin (fire-and-forget — no acknowledgement is
read back), letting the plugin perform any side effect that must happen
outside the arx-core process: a custom SIEM bridge, a legacy forwarding
pipeline, or an in-house enrichment service. The factory validates the
binary path at startup, spawns the process synchronously, and hands the
lifecycle to the registered `plugin.Sink` implementation; the subprocess
is owned for the sink's entire lifetime and shut down on `Close`.

This package is a thin registration layer. The actual implementation
(`ExecSink`, `ManagedProcess`, NDJSON protocol) lives in
`pkg/execplugin/sink.go`; `init()` here wires it into the sink registry
under the name `exec`.

## Plugin identity

| Field          | Value                  |
|----------------|------------------------|
| PluginID       | `exec`                 |
| PluginVersion  | `1.0.0`                |
| Role           | `plugin.RoleSink`      |
| InputType      | `plugin.TypeScoredEvent` |
| OutputType     | `plugin.TypeNone`      |
| Tags           | `["exec", "external", "plugin"]` |

## Configuration

`exec` is selected by setting the sink's `Type` field to `"exec"` in the
pipeline config. The factory reads one field on `sink.SinkConfig`:

| Field | Type   | Required | Description                                   |
|-------|--------|----------|-----------------------------------------------|
| `Exec` | string | yes      | Filesystem path to the plugin binary. Empty values are rejected at construction. |

The sink's `Name()` is auto-derived as `"exec:<execPath>"`; no user-facing
`name` field is consumed.

## Registration

```go
func init() {
    pkgsink.Register("exec", func(ctx context.Context, cfg pkgsink.SinkConfig) (plugin.Sink, error) {
        if cfg.Exec == "" {
            return nil, fmt.Errorf("sink type=exec requires exec field (path to plugin binary)")
        }
        return execplugin.NewSink(ctx, cfg.Exec)
    })
    pkgsink.RegisterManifest("exec", (&execplugin.ExecSink{}).Manifest())
}
```

The `ctx` is propagated into `NewManagedProcess` so the subprocess spawn
honours shutdown signals from the start (otherwise a hanging plugin binary
would block the pipeline on startup until a process-kill timeout fires).

## Behaviour

- **Startup.** `NewSink(ctx, execPath)` opens a `ManagedProcess` against
  the binary at `execPath`. Failure to spawn returns an error and the
  pipeline aborts the sink.
- **Write.** Each event is serialised as a NDJSON `WriteRequest` with
  `protoversion = "1"` and `action = "write"`, then handed to
  `ManagedProcess.Send`. The write is fire-and-forget — there is no
  `WriteAck` wait. Concurrent `Write` calls are serialised through the
  process lock.
- **Drop policy.** None — `Stats().Dropped` is hardcoded to `0`. Write
  errors increment the `Errors` counter and are returned to the caller.
- **Crash recovery.** If the subprocess dies (stdin pipe closes),
  `Write` returns `"failed to send WriteRequest: <err>"` and `Errors`
  is incremented. The sink does **not** reconnect. Recovery requires
  `Close` followed by a fresh sink construction.
- **Close.** Delegates to `ManagedProcess.Close`, terminating the
  subprocess gracefully. `Close` is not re-entrant safe in the sense
  that the same sink cannot be reopened — build a new sink instead.

## Counters

| Counter         | Source              | Notes                                  |
|-----------------|---------------------|----------------------------------------|
| `EventsWritten` | `atomic.Int64`      | Incremented after each successful send |
| `Dropped`       | hardcoded `0`       | No buffering layer in Phase 1          |
| `Errors`        | `atomic.Int64`      | Marshalling or send failures           |

## Example

```yaml
sinks:
  - type: exec
    exec: /usr/local/bin/example-siem-bridge
```

The factory spawns `/usr/local/bin/example-siem-bridge` on startup and
writes one NDJSON line per scored event to its stdin. The sink stays
attached to the same process for its entire lifetime.

## Dependencies

- `pkg/execplugin` — `ExecSink`, `ManagedProcess`, NDJSON protocol types.
- `pkg/plugin` — `Sink`, `SinkStats`, `Event`, `Manifest`.
- `pkg/sink` — `Register`, `RegisterManifest`, `SinkConfig`.