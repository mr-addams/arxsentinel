# Pipeline Validator

## Why a Validator?

The pipeline validator catches type mismatches before any event is processed — **fail-fast at daemon startup**, not fail-random at runtime.

A pipeline is a chain of plugins: `Source → Processor → ... → Sink`. Each plugin declares `InputType` and `OutputType` in its Manifest. If plugin A emits `TypeStructured` but plugin B expects `TypeRawLog`, every event will crash or produce garbage. The validator catches this before the first event flows.

Two invocation modes:

1. **Standalone validation** — `arxsentinel validate --config=pipeline.yaml` exits 0 on success, 1 with errors
2. **Daemon startup** — `arxsentinel run --config=pipeline.yaml` runs the validator as part of the boot sequence; exits immediately on mismatch

---

## Compatibility Rules

Each adjacent pair `(chain[i], chain[i+1])` is checked:

```
chain[i].OutputType  ==  chain[i+1].InputType
```

### Exact match

```go
chain[0] = Source{OutputType: TypeRawLog}
chain[1] = Processor{InputType: TypeRawLog}
// ✓ TypeRawLog == TypeRawLog — pass
```

### TypeAny — universal bridge

`TypeAny` is compatible with **any** DataType on either side. It acts as a flexible adapter:

```go
chain[0] = Processor{OutputType: TypeStructured}
chain[1] = Detector{InputType: TypeAny}
// ✓ TypeAny matches everything — pass
```

```go
chain[0] = Processor{OutputType: TypeAny}
chain[1] = Detector{InputType: TypeStructured}
// ✓ TypeAny matches everything — pass
```

### TypeNone terminal

`TypeNone` at the end of a chain means the plugin produces no data for the next stage (e.g., a Sink that only writes to storage):

```go
chain[0] = Detector{OutputType: TypeScoredEvent}
chain[1] = Sink{InputType: TypeScoredEvent}
// ✓ exact match — pass
```

If a Sink declares `InputType: TypeNone`, it must be the last in the chain and no downstream plugin can consume its output.

---

## Compatibility Table

| OutputType ↓ / InputType → | `none` | `raw_log` | `structured` | `scored_event` | `any` |
|---|---|---|---|---|---|
| **`none`** | ✓ | ✗ | ✗ | ✗ | ✓ |
| **`raw_log`** | ✗ | ✓ | ✗ | ✗ | ✓ |
| **`structured`** | ✗ | ✗ | ✓ | ✗ | ✓ |
| **`scored_event`** | ✗ | ✗ | ✗ | ✓ | ✓ |
| **`any`** | ✓ | ✓ | ✓ | ✓ | ✓ |

### Accepted patterns (safe chains)

```
Source(TypeNone)                           → side-effect only source
Source(TypeRawLog) → Processor(TypeRawLog) → Processor(TypeStructured) → Detector(TypeStructured) → Sink(TypeScoredEvent)
Source(TypeAny)    → Processor(TypeAny)    → Detector(TypeAny)         → Sink(TypeAny)
```

### Rejected patterns (mismatches)

```
Source(TypeRawLog)    → Detector(TypeScoredEvent)     # expected raw_log, got scored_event
Processor(Structured) → Processor(TypeRawLog)         # expected structured, got raw_log
Detector(ScoredEvent) → Sink(TypeRawLog)              # expected scored_event, got raw_log
```

---

## SemanticError — Output Format

When a mismatch is found, the validator returns a `SemanticError` for each broken adjacency:

```go
type SemanticError struct {
    StepIndex int
    StepAName string
    StepBName string
    Got       plugin.DataType
    Want      plugin.DataType
}
```

### Example output

```
step 0: plugin 'file-source' outputs 'raw_log' but 'ml-detector' expects 'scored_event'
```

### How to read

1. **step 0** — the mismatch is at position 0 in the chain (between first and second plugin)
2. **'file-source' outputs 'raw_log'** — the upstream plugin produces `TypeRawLog`
3. **'ml-detector' expects 'scored_event'** — the downstream plugin expects `TypeScoredEvent`

### How to fix

Insert (or reorder) a processor that converts between the types. For example:

```yaml
# Before (broken)
sources: [file-source]            # OutputType: raw_log
detectors: [ml-detector]          # InputType: scored_event  ← mismatch

# After (fixed)
sources: [file-source]            # OutputType: raw_log
processors:
  - type: log-parser              # InputType: raw_log → OutputType: structured
  - type: score-enricher          # InputType: structured → OutputType: scored_event
detectors: [ml-detector]          # InputType: scored_event  ← ✓
```

---

## Usage

### Standalone validation

```bash
arxsentinel validate --config=/etc/arxsentinel/pipeline.yaml
# Exit 0: pipeline is valid
# Exit 1: one or more SemanticErrors printed to stderr
```

### Daemon startup (fail-fast)

```bash
arxsentinel run --config=/etc/arxsentinel/pipeline.yaml
# Before processing any events, the validator runs.
# On mismatch: log each SemanticError to stderr and exit with code 1.
# On pass: proceed to start sources, open sinks, begin event loop.
```