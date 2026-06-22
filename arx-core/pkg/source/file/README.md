# `pkg/source/file` — File Source

File source plugin for ArxSentinel. Reads log events from local files,
follows appended lines, and handles log rotation. Operates in tail mode —
the preferred input method for on-disk log files produced by web servers,
system services, and any application writing to a rotating log file.

- **Plugin ID:** `file`
- **Plugin version:** `1.0.0`
- **Role:** `Source`
- **Input type:** `none`
- **Output type:** `structured`
- **Tags:** `file`, `tail`, `log-rotation`

## Module Layout

```
pkg/source/file/
├── manifest.go       # Plugin metadata (Manifest, init registration)
├── source.go         # FileSource struct, constructor, Run(), Close(), Stats()
└── source_test.go    # Tests
```

---

## Modes

The file source runs in a single mode — tail. There is no push/pull split
and no per-mode configuration: any file referenced from the input list is
followed from its current end-of-file position.

### Tail Mode (default)

The source reads the file at `path` from its current end, follows new
lines as they are appended, and handles log rotation transparently.

- The source uses `utils.TailReader` (from `internal/sys/utils/tail.go`),
  constructed with `utils.NewTailReader(path, lines, retryInterval)`.
- `TailReader` follows the file by inode on Linux (inotify) and by
  directory watch on macOS (FSEvents), so a rename/create rotation cycle
  (`logrotate` with `copytruncate` or `create`) is picked up automatically.
- If the file is absent at startup — or temporarily disappears mid-run —
  the tailer waits `retryInterval` and retries. The source does not fail
  on a missing file.
- Lines are streamed through a buffered `lines` channel of size 1000
  (`defaultLinesBufSize`). The `Run()` consumer reads serially: increment
  `linesRead`, hand the line to `parser.Parse`, non-blocking-send the
  resulting `*plugin.LogEntry` on `out`. The `Run()` loop blocks until
  the source context is cancelled.
- The downstream `out` channel is consumed by the ArxSentinel pipeline;
  if the pipeline is momentarily full, the entry is dropped and
  `dropped` is incremented.

The processing pipeline is:

```
TailReader ──line──▶ parser.Parse() ──*plugin.LogEntry──▶ out chan (non-blocking)
                          │
                          └─ !ok  → parseErrors++
                          └─ full → dropped
```

When the source context is cancelled, the tailer goroutine exits and
`Run()` returns with no error.

---

## Configuration Reference

Inputs are declared under `inputs[]` in the stream configuration. Only the
fields relevant to the file source are listed below; see the project-level
documentation for the full input schema.

| Field            | Type      | Default                                  | Required | Description                                                                                            | Validation                                                                                       |
|------------------|-----------|------------------------------------------|----------|--------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| `type`           | `string`  | —                                        | **yes**  | Must be `"file"`.                                                                                      |                                                                                                  |
| `path`           | `string`  | —                                        | **yes**  | Path to the log file on disk, e.g. `/var/log/nginx/access.log`.                                       | Must be non-empty.                                                                               |
| `parser`         | `string`  | inherited from `parser.log_format`       | no       | Parser format: `combined`, `json`, `regex`, or a custom profile name.                                 | Resolved to a `parser.Parser` instance at build time; the source fails if the parser is `nil`.   |

`retryInterval` and `logFn` are not user-facing configuration fields —
they are supplied by the build layer through `BuildOptions` and inherit
safe defaults (`5s` and a no-op logger respectively) when the caller
leaves them zero/nil.

### Validation Rules

- `type` must be exactly `"file"`; any other value is rejected at config
  parse time.
- `path` is mandatory; an empty path fails at startup with
  `"file source: path must not be empty"`.
- `parser` must resolve to a non-nil `parser.Parser` instance at build
  time. A nil parser fails with
  `"file source %s: parser must not be nil"`.
- `retryInterval`, when zero or negative, defaults to `5s`.
- `logFn`, when nil, defaults to a no-op (`nil → no-op` per the
  `pkg/source.registry.BuildOptions.LogFn` contract; previously `nil →
  utils.Log` — see Flow 072 Task 1.2.5).

---

## Parser Integration

The file source has no protocol adapters — the format is always
"newline-delimited text from a file". Parsing is delegated entirely to
the configured `parser.Parser`.

The `Parser` interface is:

```go
type Parser interface {
    Parse(line string) (*plugin.LogEntry, bool)
}
```

A line flows through the source like this:

1. `TailReader` produces a single line.
2. `linesRead` is incremented.
3. `parser.Parse(line)` is invoked:
   - If `ok == false` → `parseErrors` is incremented, a debug log
     `"file source %s: skipping malformed line: %.80s"` is emitted, and
     the loop continues with the next line.
   - If `ok == true` → the returned `*plugin.LogEntry` is sent on
     `out` via a non-blocking send; if the channel is full, `dropped`
     is incremented.

### Supported parsers

The `parser` field accepts the following names, resolved at build time
through `BuildOptions.Parser`:

- `combined` — Combined Log Format (nginx/Apache access logs).
- `json` — one JSON object per line.
- `regex` — regular-expression-based extraction (the expression is
  defined by the named parser profile).
- any custom profile name registered in the parser registry.

Example:

```yaml
inputs:
  - type: file
    path: /var/log/nginx/access.log
    parser: combined
```

---

## Log Rotation Handling

`utils.TailReader` is rotation-aware and survives the most common
log-rotation patterns out of the box.

- **Underlying mechanism.** The tailer uses `inotify` on Linux and
  `FSEvents` on macOS to receive filesystem events on the watched path.
- **Rename + create (`logrotate create`).** When the original file is
  renamed (e.g. `access.log` → `access.log.1`) and a new `access.log`
  is created in its place, the tailer closes the old inode and opens
  the new one. Lines appended after the rotation are read from the
  replacement file with no gap.
- **Copy + truncate (`logrotate copytruncate`).** When the original
  file is truncated in place, the tailer continues reading from the
  new end-of-file offset on the same inode.
- **Brief unavailability.** If the file is renamed, deleted, or
  temporarily inaccessible, the tailer waits `retryInterval` and
  reopens the path. The source does not crash and does not lose its
  state.
- **No data loss on rotation.** Any lines still in the buffered
  `lines` channel from the old file are processed before the tailer
  switches inodes, so the pipeline observes a continuous stream.

This behaviour is provided by `utils.TailReader` itself; the file
source contributes only the channel pump and the parser stage on top
of it.

---

## Metrics and Stats

The source exposes three runtime counters via `Stats() plugin.SourceStats`:

| Counter       | Type   | Description                                                | Incremented when                                                                              |
|---------------|--------|------------------------------------------------------------|-----------------------------------------------------------------------------------------------|
| `linesRead`   | int64  | Total lines read from file.                                 | Every line received from `TailReader` before parsing.                                        |
| `parseErrors` | int64  | Lines the parser could not interpret.                       | `parser.Parse()` returns `ok == false`.                                                      |
| `dropped`     | int64  | Entries dropped because downstream was full.                | Non-blocking send on `out` falls into the `default` branch (the channel is full).            |

All three counters use `sync/atomic` and are safe to read concurrently
from the metrics endpoint without taking a lock.

`Close()` is a no-op for the file source — the source is stateless with
respect to cleanup. Stopping the source is done by cancelling the
context passed to `Run()`.

---

## Constructors

A single constructor is exposed:

```go
// NewFileSource creates a new file source that tails path and sends parsed lines downstream.
// path — absolute path to the log file (e.g. "/var/log/nginx/access.log").
// p — parser.Parser for log lines; must not be nil.
// retryInterval — delay between retry attempts on file errors; 0 defaults to 5s.
// logFn — structured logger; nil is no-op (was utils.Log before Flow 072 Task 1.2.5).
func NewFileSource(path string, p parser.Parser, retryInterval time.Duration, logFn func(tag, msg, level string)) (*FileSource, error)
```

The constructor validates:
- `path` must be non-empty — empty path returns
  `"file source: path must not be empty"`.
- `p` (parser) must not be nil — nil returns
  `"file source %s: parser must not be nil"`.
- `retryInterval` — zero or negative values default to `5 * time.Second`.
- `logFn` — nil is replaced with a local no-op per the
  `pkg/source.registry.BuildOptions.LogFn` contract.

The constructor is non-blocking and returns immediately with a fully
configured instance or an error.

---

## Registration

The plugin is registered in `init()`:

```go
func init() {
	pkgsource.Register("file", func(cfg pkgsource.InputConfig, opts pkgsource.BuildOptions) (plugin.Source, error) {
		return NewFileSource(cfg.Path, opts.Parser, opts.RetryInterval, opts.LogFn)
	})
	pkgsource.RegisterManifest("file", (&FileSource{}).Manifest())
}
```

The factory extracts `Path` from `InputConfig` (the only mandatory field)
and `Parser`, `RetryInterval`, `LogFn` from `BuildOptions`. The manifest
declares the plugin as a `Source` with `InputType: none` and
`OutputType: structured`, tagged `file`, `tail`, `log-rotation`.

---

## EOF and Cancellation

The source has a single exit path, always clean:

- **Context cancellation** — `ctx.Done()` fires. The `TailReader` goroutine
  observes the cancelled context and exits. Closing the tailer causes the
  `lines` channel to be closed. The main `Run()` loop iterates over the
  remaining buffered lines (the channel is drained), then exits with a
  `nil` return.

There is no EOF path: unlike `stdin`, a log file never signals EOF in the
traditional sense — the tailer follows the file indefinitely. There is no
scanner-error path: the `TailReader` handles file read errors internally by
retrying after `retryInterval`.

### Close()

`Close()` is a **no-op** on `FileSource`. The `TailReader` lifetime is
owned by the context passed to `Run()` — cancelling the context is the
only correct way to stop the source.

---

## Quick-Start Examples

The following snippets are self-contained, copy-pasteable fragments for
`inputs[]`. Each one assumes the rest of the ArxSentinel stream
configuration is in place.

### Tail a standard access log

```yaml
inputs:
  - type: file
    path: /var/log/nginx/access.log
    parser: combined
```

### Tail a JSON application log

```yaml
inputs:
  - type: file
    path: /var/log/app/json.log
    parser: json
```

### Tail with a regex parser

```yaml
inputs:
  - type: file
    path: /var/log/custom/app.log
    parser: regex
```

### Two independent file sources (multi-input)

```yaml
inputs:
  - type: file
    path: /var/log/nginx/access.log
    parser: combined
  - type: file
    path: /var/log/nginx/error.log
    parser: combined
```

---

## Edge Cases

The tail-based reader is designed to survive filesystem-level surprises
without taking the whole source down.

- **File not found at startup.** The tailer retries with `retryInterval`;
  the source does not fail — it waits. As soon as the file appears, the
  pipeline starts emitting entries.
- **File deleted mid-run.** The tailer detects the `inotify`/`FSEvents`
  remove event and waits for the path to reappear. The source remains
  alive and resumes tailing on the next successful reopen.
- **Log rotation (rename + create, or copy + truncate).** The tailer
  follows the inode (Linux) or watches the directory (macOS) and
  seamlessly switches to the new file. No data is lost across the
  rotation boundary.
- **Permission denied.** Logged as an error; the retry loop continues
  with `retryInterval`. Useful for catching the case where a service
  starts before its log file is created with the right ownership.
- **Empty lines.** `TailReader` does not emit empty lines. If an empty
  string somehow reaches `parser.Parse()`, the parser itself decides
  what to do; in practice this means `!ok` and an increment of
  `parseErrors`.
- **Downstream back-pressure.** When the consumer of `out` cannot keep
  up, the source stops blocking on send (the channel is non-blocking
  from the producer's side) and `dropped` rises monotonically. No
  goroutines are leaked: cancellation of the source context terminates
  the tailer and `Run()` returns.

---

## Extending

The file source is intentionally small — there is one mode, one input
format, and one extension surface: the parser.

### Adding a new parser

1. **Implement the `parser.Parser` interface** — `Parse(line string) (*plugin.LogEntry, bool)`.
2. **Register the parser** in the parser registry (typically in
   `internal/core/parser/`).
3. **Wire it up in configuration** — the new parser becomes available
   by name in the `parser` field of any `type: file` input.
4. **Document it** — add a Quick-Start example and a note on the
   expected line format.

### Modifying the source itself

When the file source itself needs new behaviour, the changes are
localised to `source.go`:

- `Run()` loop — change the line processing pipeline (e.g. add
  pre-processing, batching, or filtering between `TailReader` and
  `parser.Parse`).
- `Stats()` — add new atomic counters alongside the existing three
  and surface them in `plugin.SourceStats`.
- `NewFileSource()` — add new constructor parameters for the new
  configuration knobs, taking care to preserve the validation contract
  (path non-empty, parser non-nil, defaulting of optional parameters).

The `TailReader` → `Parser` → `out` pipeline is deliberately narrow, so
most changes stay well under 100 lines.

---

## Dependencies

Standard library:

- `context` — cancellation propagation.
- `fmt` — error and log message formatting.
- `sync/atomic` — counters (`linesRead`, `parseErrors`, `dropped`).
- `time` — `retryInterval` for file retry logic.

Project:

- `internal/core/parser` — `parser.Parser` with
  `Parse(line) → (*plugin.LogEntry, bool)`.
- `internal/sys/utils` — `utils.TailReader` (file follow with inotify).
  The legacy `utils.Log` default fallback was removed in Flow 072
  Task 1.2.5; the source is now nil-safe with a local no-op. This
  package is still imported for `TailReader` only — removing it is
  the subject of Phase 1.3 (Tail Abstraction).
- `pkg/plugin` — `Source`, `Manifest`, `SourceStats`, `LogEntry`.
- `pkg/source` — registry (`Register`, `RegisterManifest`, `InputConfig`,
  `BuildOptions`).
