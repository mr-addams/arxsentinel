# `pkg/source/file`

File source for `arx-core`. Tails a local log file from its current
end-of-file position, follows appended lines, and handles log rotation
through the platform-specific `pkg/tail` reader (inotify on Linux,
FSEvents on macOS). Each tailed line is handed to the configured
`Parser` and the resulting `*parser.LogEntry` is offered downstream via
a non-blocking send — a full channel drops the entry and increments
`Dropped`. The reader retries every `retryInterval` when the file is
absent at startup or temporarily disappears mid-run (e.g. during
`logrotate`), so a missing file is not a fatal error.

## Public API

```go
// FileSource — tails one path and delivers parsed entries.
// Implements plugin.Source.
type FileSource struct { /* unexported */ }

// NewFileSource — path must be non-empty. parser (arx-core/pkg/parser)
// must not be nil. retryInterval ≤ 0 defaults to 5s. logFn is nil-safe —
// nil falls back to an internal no-op per the
// pkg/source.BuildOptions.LogFn contract.
func NewFileSource(path string, p parser.Parser, retryInterval time.Duration, logFn func(tag, msg, level string)) (*FileSource, error)

// plugin.Source interface — implemented by FileSource.
func (s *FileSource) Name() string                       // returns "file:<path>"
func (s *FileSource) Run(ctx context.Context, out chan<- *plugin.Event) error
func (s *FileSource) Close() error                      // no-op: tailer lifetime is owned by the Run() context
func (s *FileSource) Stats() plugin.SourceStats         // LinesRead / ParseErrors / Dropped
```

The source registers itself as `type: file` via `init()` and uses
`pkgsource.InputConfig.Path` plus `pkgsource.BuildOptions.{Parser,
RetryInterval, LogFn}`. Log rotation is picked up automatically by the
underlying `pkg/tail.TailReader` — the source itself only owns the line
pump and parser stage.

## Example

Tail an nginx access log through the combined-format parser:

```yaml
inputs:
  - type: file
    path: /var/log/nginx/access.log
    parser: combined
```
