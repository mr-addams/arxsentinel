# pkg/plugin

The plugin contract package. Every plugin — whether shipped as a base plugin
in the `arx-core` library or written by a host product — depends on the types
declared here and nothing host-internal. That single rule is what makes a
plugin movable between a product and the core library with only an import-path
change (Flow 083, Principle 5 / location-independence).

`pkg/plugin` holds **contract types only**: plugin role/identity, the data-flow
envelope, the generic event carrier, and the field-level contract a plugin
declares in its manifest. Concrete domain models (an HTTP log line, a scored
detection result) are **not** declared here — they belong to the plugin that
produces or consumes them.

## Data model

### `Envelope` — transport metadata

```go
type Envelope struct {
    Timestamp  time.Time // time of the originating record
    Stream     string    // stream name; empty in single-stream mode
    Source     string    // source identifier, e.g. "file:/path" or "stdin"
    SourceType string    // source kind: "file", "stdin", "http", ...
    Level      string    // severity label, values defined by the host product
}
```

`Envelope` is the **only** payload-shaped data the engine itself reads. The
runtime inspects envelope fields for metrics and routing — counting events per
stream, per source, per level — which is a legitimate engine function, not a
leak. The engine never reads the product payload (see `Event` below).

`Level` is a free string: the engine compares it for metric bucketing, but the
**values** (`"WARN"`, `"THREAT"`, `"INFO"`, …) are defined by the host product,
not by the core. The core attaches no meaning to any particular level string.

### `Event` — generic event carrier

```go
type Event struct {
    Envelope        // transport metadata the engine reads
    Payload  any    // opaque product data the engine never inspects
}
```

`Event` is what flows from a producer plugin to a consumer plugin through the
engine. `Payload` is deliberately `any`: the core does not know — and must not
know — the concrete payload type. The **owning plugins** agree on the concrete
type; a consumer type-asserts `Payload` to its expected shape.

Type safety is recovered at startup, not via runtime panics: a plugin declares
the fields it produces/consumes in its manifest (`FieldDecl`, below), and the
pipeline's field-level validator fails fast before any data flows if a
consumer's required field has no upstream producer.

### `FieldDecl` + `Manifest.Produces` / `Manifest.Consumes` — field contract

```go
type FieldDecl struct {
    Name     string // symbolic field identifier
    Required bool   // mandatory for a consumer; producer omission fails startup
}

type Manifest struct {
    // ... identity (PluginID, Role, InputType, OutputType, Tags) ...
    Produces []FieldDecl // fields this plugin emits in its output payloads
    Consumes []FieldDecl // fields this plugin requires/accepts on input
}
```

A producer lists the named fields it emits; a consumer lists the fields it
needs. The field-level validator checks, for every adjacent pair in a pipeline,
that `producer.Produces` is a superset of `consumer.Consumes` by `Name`, with
`Required` participating in the comparison.

`FieldDecl` is intentionally minimal — `Name` plus `Required`, no `Type`. A type
field can be added later if the validator ever needs to reason beyond
name-presence; keeping it minimal preserves back-compat and avoids dragging in
reflection-based schemas. A plugin that leaves `Produces`/`Consumes` nil
declares "no field contract" and is treated as compatible with any field shape
(the coarse `DataType` check still applies).

## Identity and roles

`Manifest` also carries plugin identity (`PluginID`, `PluginVersion`, `Role`)
and the coarse data-type contract (`InputType`/`OutputType` as `DataType`).
`DataType` remains the coarse classifier; `FieldDecl` is the fine-grained layer
on top of it.

## Boundary

- `pkg/plugin` imports stdlib only — no host-internal packages, no product
  vocabulary baked into contract types.
- A plugin that cannot move core↔product with only an import-path change has
  leaked a host dependency. That is the mechanical cleanliness test for any
  plugin built on this contract.
