# pkg/processorplugins/waf — WAF Processor

The WAF processor compiles a set of WAF rules from a YAML configuration into two typed
`RuleSet`s (via `github.com/mr-addams/arx-core/pkg/rule`) and, for every event reaching
the processor stage, evaluates those rules against the event's `http.*` fields using a
**two-pass scheme**: pass-rules (whitelist, `action: pass`) run first and short-circuit
on match; gate-rules (threat, `action: drop` or `action: tag[:<label>]`) run only if no
pass-rule fired. The gate rule's `action` decides the verdict: `drop` gates the event
out of the pipeline, `tag` flags it for downstream scoring by stamping the Envelope
`Level`, and `tag:<label>` adds a score-signal delta through the `ScoreFunc` closure.
This is the canonical Flow 001 implementation of "engine returns the verdict, plugin
decides the action" (DECISION D12).

The WAF processor is **not** a rate-limiter, not a geo-blocker, and not a regex-on-raw-line
matcher. It is a stateless predicate gate over the already-parsed `parser.LogEntry`,
designed to compose with the project's other plugins (chaincheck, whitelist) and to
extend the same rule language that arx-core's detectors already use. Because the
RuleSet is compiled once at Init and evaluated per event, a 3-rule config can be
re-evaluated at >2.5 M events/sec on commodity x86 hardware — see
[Performance characteristics](#11-performance-characteristics).

The pipeline calls `Process` for every structured log entry that reaches the processor
stage. The consumer is the next stage in the pipeline (a detector, scorer, or sink) —
it receives only entries that survived WAF filtering.

## 1. Overview

The WAF processor applies a curated rule set to HTTP traffic surfaced by the parser
layer. Each rule is a name, an expression in the arx-core rule DSL, and an action. At
runtime the processor's only job is to:

1. Receive a `*plugin.Event` whose `Payload` is a `*parser.LogEntry`.
2. Run the **pass-rules** `RuleSet` (whitelist, `action: pass`). On match — short-circuit
   and pass the event through unchanged.
3. If no pass-rule matched, run the **gate-rules** `RuleSet` (threat, `action: drop` or
   `action: tag[:<label>]`). On the first match, dispatch that rule's action.
4. On no match in either pass, pass the event through unchanged.

The two-pass split is enforced at compile time by `NewRuleSetFromConfig`
(`ruleset.go`): every rule is bucketed by its `action` field into either `passRules`
or `gateRules`, and the wire-up code never inspects the bucket at evaluation time —
each pass owns its own compiled `RuleSet`. That split is what makes the WAF rules
live-reloadable in principle (replace a rule in either `RuleSet`) without
re-instantiating the processor.

Typical use cases:

- Blocking scanner traffic by matching `http.user_agent matches "sqlmap.*"` → `drop`.
- Tagging admin-path probes for downstream scoring (`http.path contains "/admin"`)
  → `tag` or `tag:<label>` to feed the score signal.
- Allowlisting internal health checks (`http.path eq "/healthz"` → `action: pass`)
  so they short-circuit before any gate rule can fire.
- Combining method and status: `http.method eq "POST" and http.status eq 405` → `drop`.

The plugin is part of Flow 001 of the WAF rule-engine work; the remaining Flow 001
task is documentation polish (cookbook + config reference) which is tracked outside
this release.

## 2. Architecture

```
  Event.Payload (*parser.LogEntry)
          │
          ▼
    chainedResolver ─┬─ EnvelopeResolver  (core.* namespace, owned by arx-core)
                     └─ HttpResolver      (http.* namespace, type-asserts to *LogEntry)
          │
          ▼
    WafProcessor.Process(ctx, event)
          │
          ├──► Pass 1: passRules.Match(event, resolver)
          │       ── match ──► (event, nil)         (event flows on, gate skipped)
          │       ── miss  ──► continue ▼
          │
          └──► Pass 2: gateRules.Match(event, resolver)
                  ── match ──► action dispatch
                                  ├── drop       → (nil, nil)
                                  ├── tag        → (event, Level="THREAT:<rule>")
                                  ├── tag:<lbl>  → (event, Level="THREAT:<rule>:<lbl>")
                                  │              + ScoreFunc(ip, weight)
                                  └── unknown    → fail-closed drop (nil, nil)
                  ── miss  ──► (event, nil)         (event flows on)
```

The architectural boundaries that matter for anyone reading or extending the plugin:

- **Two-pass evaluation.** `NewRuleSetFromConfig` (`ruleset.go`) splits the configured
  rules into two `RuleSet`s at compile time: `passRules` (every rule with
  `action: pass`) and `gateRules` (every rule with `action: drop` or `action: tag`).
  The runtime walks `passRules` first; on a hit the gate is skipped entirely. This
  is *not* order-dependent within the gate pass — the bucket itself is the
  declaration of intent. The two `RuleSet`s share the same resolver chain and the
  same field catalog; only the bucket differs.

- **Engine does not touch `Payload`** (DECISION D3). The rule engine sees only the
  `*plugin.Event` envelope and asks the resolver chain for typed `Value`s of any
  field an expression references. The engine never inspects `event.Payload` directly,
  which means the engine can be reused for non-HTTP profiles as long as the resolver
  chain can answer the relevant fields.

- **Engine does not execute actions** (DECISION D12). The engine returns a
  `(ruleName, matched)` tuple per pass. The plugin turns `matched=true` into one
  of four outcomes: `(nil, nil)` for `drop`, `(event, nil)` for `tag` (with
  `Level = "THREAT:<rule>"`), `(event, nil)` for `tag:<label>` (same plus a score
  signal), and a fail-closed `(nil, nil)` for any unknown action.

- **Compile-once / eval-many** (DECISION D4). `NewWafProcessor` compiles the
  configuration's rule expressions at Init time into both `RuleSet`s. A bad
  expression fails the entire `NewWafProcessor` call (fail-fast, D13) — it never
  makes it into a partially populated `RuleSet`. Once compiled, every `Process`
  call is a read-only walk over the two `RuleSet`s under its internal `RWMutex`.

- **Stateless resolver chain.** `HttpResolver` carries no fields; the
  `chainedResolver` constructed in `processor.go` is shared across every event.
  The same instance may be called from many goroutines without coordination.

## 3. Supported fields

Every field below is declared in `manifest.go` (`Manifest.Produces`) and answered by
the `HttpResolver` (`resolveHTTP` in `resolver.go`). The full name in expressions is
`http.<name>` (the namespace separator is the dot, per DECISION D7). The `Type`
column mirrors the `plugin.FieldType` constant in arx-core; rules type-check at
compile time against these.

| Field | Type | Source (`parser.LogEntry`) | Notes |
|-------|------|------------------------------|-------|
| `http.method` | string | `.Method` | HTTP method (`GET`, `POST`, …) |
| `http.path` | string | `.Path` | Path without query string |
| `http.query` | string | `.Query` | Raw query string (with leading `?` stripped) |
| `http.raw_uri` | string | `.RawURI` | Full request URI (path + query) |
| `http.status` | int | `.Status` | HTTP response status code |
| `http.bytes_sent` | int | `.BytesSent` | Response body size in bytes |
| `http.referer` | string | `.Referer` | `Referer` header value |
| `http.user_agent` | string | `.UserAgent` | `User-Agent` header value |
| `http.remote_addr` | ip | `.RemoteAddr` | Direct peer (transport-level); parsed with `net.ParseIP` |
| `http.real_ip` | ip | `.RealIP` | `real_ip` extracted by the parser; same parsing rules as `remote_addr` |
| `http.protocol` | string | `.Protocol` | `HTTP/1.1`, `HTTP/2`, … |
| `http.remote_user` | string | `.RemoteUser` | Authenticated user (if any) |

Empty strings in IP-typed fields (`http.real_ip` / `http.remote_addr`) resolve to
unmatched (the resolver returns `(Value{}, false)`) rather than matching the zero
IP `0.0.0.0`. The same applies to CIDR literals — they are rejected as a parse error
because the rule engine's CIDR operators work on already-parsed `KindIP` values; a
CIDR string in `LogEntry` is treated as a configuration bug, not a match candidate.

## 4. Expression language reference

WAF rules use the same expression language as the rest of arx-core's rule-driven
components (detectors, scoring chains). The full grammar, operator precedence, and
semantics are documented in arx-core:

- [`github.com/mr-addams/arx-core/pkg/rule/REFERENCE.md`](https://github.com/mr-addams/arx-core/blob/v0.2.0/pkg/rule/REFERENCE.md) — language reference (operators, literals, type promotion).
- `pkg/rule/builder` (in arx-core) — the `Builder` API the WAF plugin uses to
  compose a typed `RuleSet` from `Manifest.Produces`.

The supported operator set covers the operators the WAF plugin's integration tests
exercise:

- **Comparison:** `eq`, `ne`, `lt`, `le`, `gt`, `ge` (works for `string`, `int`,
  `ip`, `timestamp`).
- **String match:** `contains`, `starts_with`, `ends_with`, `matches` (RE2).
- **Glob:** `wildcard` (case-insensitive shell-style patterns).
- **Membership:** `in` (against an array literal; for IP, against a CIDR list).
- **Boolean combinators:** `and`, `or`, `not`, with parentheses for grouping.

Literal forms: `"..."` for strings, integer / float for numbers, `ip"..."` for IP
literals, `ts"RFC3339"` for timestamps, `0x"hex"` for byte strings, Go duration
(`"5m"`, `"2h30m"`) for durations, and `[a, b, c]` for array literals.

A cookbook of reusable rule patterns (e.g. "block common scanners", "allowlist
healthchecks", "geo block by CIDR") is not part of this release — the Flow 001
work covers the engine and the integration surface, and the cookbook is the next
flow's deliverable.

## 5. Configuration

The WAF processor is declared under `processors[]` in the stream configuration. The
plugin's typed config lives under `params["waf_config"]` (key from
`register.go` `ParamKeyConfig`):

```yaml
processors:
  - plugin: waf
    params:
      waf_config:
        rules:
          - name: block_post_405
            expression: 'http.method eq "POST" and http.status eq 405'
            action: drop
          - name: tag_admin_path
            expression: 'http.path contains "/admin"'
            action: tag
          - name: pass_healthcheck
            expression: 'http.path eq "/healthz"'
            action: pass
```

- The top-level key is `params` (a `map[string]any`).
- The `waf_config` value is a `waf.Config` (the plugin's typed struct from
  `ruleset.go`); the factory in `register.go` performs the type assertion at wire-up
  time and returns an error if the key is missing or has the wrong type.
- Each rule is a `waf.RuleConfig` (also from `ruleset.go`): `name`, `expression`,
  `action`. `action` is optional — see [Actions](#8-actions) for the default.

A more comprehensive reference (`config.reference.yaml` with annotated examples
covering CIDR lists, RE2 patterns, multi-rule compound expressions, and so on) is
the deliverable of Flow 001's documentation task, not this release.

## 6. Profile / scheme used

The WAF plugin's rule surface is the `"http"` profile — both the namespace in
expressions (`http.<field>`) and the profile name passed to the arx-core
`builder.New("http")` constructor. The "http" profile is implicit in
`NewRuleSetFromConfig` (`ruleset.go`); the `BuildScheme` function is a separate
introspection-only entry point that registers the same field set without compiling
any rules, useful for config-validation tooling.

Every scheme also carries the implicit `core.*` namespace (`Envelope` fields:
`timestamp`, `stream`, `source`, `source_type`, `level`). WAF rules can therefore
reference both namespaces — for example:

```text
http.status eq 401 and core.source eq "nginx"
```

The `core.*` fields are answered by `rule.EnvelopeResolver` (arx-core), the
`http.*` fields by the plugin's `HttpResolver`. The processor's
`chainedResolver` dispatches in that order. Multi-profile schemes (for example, an
"app" profile that adds application-specific fields) are not part of this
release — the WAF plugin only knows about `http` plus the implicit `core`.

## 7. Rule format

Each rule is a `RuleConfig` (in `ruleset.go`):

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `name` | yes | string | Unique rule name; appears in error messages, in the `THREAT:<rule>` tag, and as the `Match` return value. |
| `expression` | yes | string | Rule DSL expression (see [Expression language reference](#4-expression-language-reference)). |
| `action` | no | string | `"drop"` (default), `"tag"`, `"tag:<label>"`, or `"pass"`. Case-insensitive. Unknown values fall back to `"drop"`. |

The action's **bucket** is determined by its prefix:

| Action | Bucket | Effect |
|--------|--------|--------|
| `pass` | `passRules` | Whitelist short-circuit (see [Two-pass evaluation](#8-actions)) |
| `drop` | `gateRules` | Gate the event out of the pipeline |
| `tag` | `gateRules` | Overwrite `Level = "THREAT:<rule>"` and pass through (Level contract — see [Envelope.Level contract](#envelope-level-contract)) |
| `tag:<label>` | `gateRules` | Overwrite `Level = "THREAT:<rule>:<label>"` **and** call `ScoreFunc(ip, weight)` (Level contract — see [Envelope.Level contract](#envelope-level-contract)) |

Example:

```yaml
- name: block_scanners
  expression: 'http.user_agent matches "(sqlmap|nikto|nuclei)/[0-9.]+"'
  action: drop
- name: tag_admin_probes
  expression: 'http.path contains "/admin" and http.status ge 400'
  # action omitted — defaults to "drop" (fail-closed)
- name: tag_4xx_flood
  expression: 'http.status ge 400 and http.status lt 500'
  action: 'tag:4xx-flood'    # feeds the score signal with label "4xx-flood"
- name: pass_healthcheck
  expression: 'http.path eq "/healthz"'
  action: pass
```

Empty `name` or empty `expression` is rejected at Init time with a descriptive
error (the rule index or rule name is included in the message). This is part of
the fail-fast contract: misconfigured rules never make it into a partially
populated `RuleSet` (DECISION D13).

## 8. Actions

The action is the WAF plugin's interpretation of a `Match` verdict (DECISION D12:
the engine returns the verdict, the plugin decides). The action's first token
determines which pass owns the rule — see [Rule format](#7-rule-format) for the
bucketing rule.

**Two-pass evaluation** (replaces the earlier first-match-wins contract). At Init
time, every rule is classified by its action prefix into one of two compiled
`RuleSet`s:

- `passRules` — bucket for `action: pass` only. Run first.
- `gateRules` — bucket for `action: drop` / `tag` / `tag:<label>`. Run only on
  a `passRules` miss.

On `passRules` match the event flows through unchanged and the gate is skipped
entirely — *regardless* of what gate rules would have matched. On `passRules`
miss, the gate pass runs to its first match (or to the end). The split is
declared by action, not by rule position in `Config.Rules`, so the YAML order of
pass and gate rules is free.

The action dispatch table is exhaustive (any other value falls back to `drop`):

| Action | Return value | Side-effect | Bucket | Use case |
|--------|--------------|-------------|--------|----------|
| `drop` | `(nil, nil)` | event gated out of pipeline | gate | Block: 405/403 paths, scanner patterns |
| `tag` | `(event, nil)` | `event.Envelope.Level = "THREAT:<rule>"` (prior Level overwritten — D3) | gate | Flag for downstream scoring/sink without blocking |
| `tag:<label>` | `(event, nil)` | same as `tag` with `"THREAT:<rule>:<label>"` (prior Level overwritten — D3) **plus** `ScoreFunc(ip, weight)` | gate | Feed the score signal so a tagged rule contributes to ban decisions |
| `pass` | `(event, nil)` | unchanged; gate is skipped | pass | Allowlist / healthcheck rules (short-circuit) |
| (default) | `(nil, nil)` | fail-closed drop | gate | Unknown action value — safe default for WAFs |

`tag` stamps the matched rule's name into the envelope's `Level` field as
`"THREAT:<rule>"`. The `tag:<label>` form appends the label after a second colon
(`"THREAT:<rule>:<label>"`). Downstream stages that already parse `Level` (the
scorer, the sinks) can split on the colon to recover the rule name (and, for the
labeled form, the label) when they care to. The processor's signature guarantees
that only one rule's name appears there per event.

### Envelope.Level contract

The `Envelope.Level` overwrite on a `tag` / `tag:<label>` hit is an **explicit
contract** of the WAF plugin (DECISION D3), not an incidental side-effect.
Codifying it prevents future drift where a well-meaning change tries to merge
Levels.

- **Format** (two shapes):

  ```
  THREAT:<rule-name>          // action="tag"
  THREAT:<rule-name>:<label>  // action="tag:<label>"
  ```

- **Single owner of the `THREAT:` prefix.** The WAF plugin is the only plugin
  in arxsentinel that writes this namespace. Other plugins that want
  rule-encoded routing must define their own prefix (e.g. `GEO:<country>`);
  overloading `THREAT:` would create cross-plugin coupling.

- **Prior `Level` is intentionally OVERWRITTEN.** A tag-rule firing means the
  event is now classified as a threat by this WAF, and downstream sinks /
  executors route on `Level`. Carrying forward an unrelated prior `Level`
  would create ambiguity (is the event tagged by WAF or by some upstream
  plugin?). For an audit trail of pre-WAF `Level`, the rule's `name` (encoded
  in the new `Level`) plus the rule's expression are sufficient forensics —
  no passthrough of the prior value is performed.

This is NOT a sanctioned general pattern for "encoding structured routing
data into `Level`" — it is a WAF-specific contract. Any future change that
wants to add per-rule metadata should model it as a new `Envelope` field in
arx-core, not as another `THREAT:`-prefixed string.

`tag:<label>` *also* calls the `ScoreFunc` closure (see
[Scoring integration](#9-scoring-integration-scorefunc-dropscore-tagweights)).
That call is what ties WAF hits into the same scoring pipeline the detectors
already drive — a labelled tag is the WAF plugin's way of saying "this event
should count against IP X's score, by `weight` points, attributed to `label`".

## 9. Scoring integration — ScoreFunc, DropScore, TagWeights

The WAF processor can feed the per-IP scoring pipeline that the rest of
arxsentinel already drives. This is what makes `tag:<label>` rules more than a
log marker — a labelled tag *contributes* to the ban decision by adding a
configured delta to the offending IP's score.

Three knobs control the integration. None of them are required; if `ScoreFunc`
is `nil` (the default), the WAF processor still gates and tags as documented but
the score signal is a no-op.

### 9.1 ScoreFunc

`ScoreFunc` is a closure the wire-up code (`buildWafProcessor` in
`cmd/arxsentinel/processor_factory.go`) builds and injects into the WAF
processor at Init time:

```go
type ScoreFunc func(ip string, delta int)
```

- `ip` — the event's offending IP, taken from `http.real_ip` (falls back to
  `http.remote_addr` if `real_ip` is empty).
- `delta` — the resolved score delta for the matched rule. For a `drop` action
  this is `DropScore`; for a `tag:<label>` action it is the weight looked up
  from `TagWeights[label]` (missing label → `0`, which is a no-op).

The label from `action: tag:<label>` is **not** a parameter of `ScoreFunc`.
The wire-up closure consumes the label internally to look the weight up in
`TagWeights` and pass only the computed `delta` to `ScoreFunc`. The bare
`tag` form does not call `ScoreFunc` at all (it has no label, hence no
weight to resolve).

The closure captures the live `tracker` reference, so every `ScoreFunc` call
ends up writing into the same `tracker.GetState(ip)` slot the detectors use.
This is what makes WAF hits and detector hits stack against the same ban
threshold.

### 9.2 DropScore

`DropScore` is the integer delta added to the score *implicitly* when a
`drop`-action rule fires. It exists so that a single WAF drop is not a silent
event — a banned source still pays the price it would have paid if a detector
had flagged it.

- **Default value:** `DropScore = cfg.Scoring.BanThreshold` (the configured
  threshold for auto-banning). The rationale is "a hard drop should at least
  *reach* the threshold, so the IP is banned on the way out". Wire-up in
  `buildWafProcessor` sets this fallback automatically when the operator
  doesn't override.
- **Override:** pass `params["waf_drop_score"]: <int>` in the processor block.
  Set it lower (e.g. half the ban threshold) to *contribute* rather than
  *trigger*, or higher to make WAF drops dominate the score.
- **Wire-up key:** the factory in `register.go` reads `waf_drop_score` (see
  `ParamKeyDropScore`); missing key → fallback to `BanThreshold`.

### 9.3 TagWeights

`TagWeights map[string]int` is the per-label delta table for `tag:<label>`
rules. The lookup is exact-match on the label string; a label not present in
the map (or a `nil` map) resolves to a delta of `0`, which is a no-op against
the score.

```yaml
processors:
  - plugin: waf
    params:
      waf_config:
        rules:
          - name: tag_4xx_flood
            expression: 'http.status ge 400 and http.status lt 500'
            action: 'tag:4xx-flood'
          - name: tag_admin_probe
            expression: 'http.path contains "/admin"'
            action: 'tag:admin-probe'
      waf_tag_weights:
        "4xx-flood":    10      # repeated 4xx contributes, but does not auto-ban
        "admin-probe":  25      # admin-path probes are scored higher
```

- **Wire-up key:** `waf_tag_weights` (see `ParamKeyTagWeights`); missing key →
  empty map, every labelled tag contributes `0`.
- **Type:** `map[string]int`. Keys are label strings; values are integer deltas.
- **Resolution:** `weights[label]` if present, otherwise `0`. The lookup never
  errors — an unconfigured label is treated as a documentation oversight, not a
  misconfiguration.
- **The bare `tag` form does not call `ScoreFunc`.** Use `tag:<label>` if you
  want the score signal; use `tag` for envelope-only marking.

### 9.4 When the signal fires

`ScoreFunc` is invoked once per gate-rule match (not per pass — the pass-rules
short-circuit path never produces a score signal). The call happens after the
rule's action dispatch has already resolved `drop` / `tag` / `tag:<label>`,
so the IP that gets scored is the same IP that was just gated or tagged.

## 10. Auto-discovery via Builder.FromManifest()

`NewRuleSetFromConfig` (`ruleset.go`) uses `builder.New("http")` and iterates over
`Manifest.Produces` to register every typed field automatically:

```go
b := builder.New("http")
for _, fd := range manifest.Produces {
    b.Field("http", fd.Name, fd.Type)
}
```

This is the "auto-discovery" surface: the rule engine's `Builder` reads the
declarations in `Manifest.Produces` and produces a typed `Scheme` whose field
catalog matches what `HttpResolver` can answer. The two stay in lockstep because
the iteration is over the same struct.

The implication for plugin maintainers: as long as a new field is added to
`Manifest.Produces` and to the `resolveHTTP` switch (see
[Adding custom fields](#10-adding-custom-fields)), the rule engine will accept
expressions that reference it, with the right type, with no further changes to
`ruleset.go`. There is no manual `Register` call to add or remove.

`BuildScheme` is the introspection-only sibling: it returns a `*rule.Scheme`
without compiling any rules. It is useful for config-validators that want to
check "is this expression well-typed?" before sending the config to
`NewWafProcessor`.

## 11. Adding custom fields

To add a new `http.*` field — for example, a hypothetical `http.tls_version`
exposing the TLS handshake's negotiated version — three steps are enough:

1. **Declare the field** in `manifest.go` `Manifest.Produces`:

   ```go
   {Name: "tls_version", Type: plugin.TypeString},
   ```

2. **Answer the field** in `resolver.go` `resolveHTTP` (one new case in the
   switch):

   ```go
   case "tls_version":
       return rule.NewString(entry.TLSVersion), true
   ```

3. **(No `ruleset.go` change required.)** `NewRuleSetFromConfig` iterates
   `Manifest.Produces` and registers every field automatically. The new field is
   immediately usable in any rule expression as `http.tls_version`.

After the change:

- A rule that references the new field will compile and type-check (because the
  field is in the catalog).
- A rule that references the field on an event whose `LogEntry` does not carry
  it will resolve to unmatched (`(Value{}, false)`) — the same behaviour as any
  other empty string field.
- Tests should add a table-driven case to `resolver_test.go` covering the new
  field (both populated and empty), and a rule-level test to `processor_test.go`
  exercising at least one match and one no-match through the new field.

The exhaustive `switch` in `resolveHTTP` is intentional: it keeps the hot path
alloc-free (no map hashing on every `Resolve` call) and makes the new-field
contract — "you added a case, you get a match" — a compile-time fact. A
regression test on the catalog (every `Manifest.Produces` field has a matching
case in `resolveHTTP`) is a useful follow-up but is not in this release.

## 11. Performance characteristics

Benchmarks collected on an AMD Ryzen 9 7940HS (12 cores, single socket), Go 1.26,
`go test -bench=BenchmarkWafProcessor -benchmem -run=^$ -count=3`. Configuration:
`defaultConfig()` — three rules (`block_post_405`, `tag_admin_path`,
`pass_healthcheck`).

| Path | Throughput (events/sec) | Latency (ns/op) | Allocs/op |
|------|--------------------------|------------------|-----------|
| No-match passthrough (the production-hot path) | ~2.6 M | ~390 ns | 0 |
| Match (`drop` action) | ~3.2 M | ~315 ns | 0 |

Raw `go test -bench` output (3 runs per benchmark):

```
BenchmarkWafProcessor_HotPath-12               2989578    393.6 ns/op    0 B/op    0 allocs/op
BenchmarkWafProcessor_HotPath-12               3104421    383.2 ns/op    0 B/op    0 allocs/op
BenchmarkWafProcessor_HotPath-12               3117181    387.1 ns/op    0 B/op    0 allocs/op
BenchmarkWafProcessor_HotPathWithMatch-12      3822000    313.9 ns/op    0 B/op    0 allocs/op
BenchmarkWafProcessor_HotPathWithMatch-12      3835810    317.9 ns/op    0 B/op    0 allocs/op
BenchmarkWafProcessor_HotPathWithMatch-12      3954630    314.9 ns/op    0 B/op    0 allocs/op
```

The headline numbers:

- **Zero allocations on the hot path.** `0 B/op`, `0 allocs/op` on both
  no-match and match paths confirms DECISION D4: the `RuleSet.Match` and the
  resolver chain are alloc-free for the common case. The single allocation per
  event in production comes from outside the processor (the `*plugin.Event` and
  the `*parser.LogEntry`), not from WAF processing itself.
- **~2.6 M events/sec** on the no-match path is what the WAF plugin will sustain
  when no rule fires — the production steady state. `3.2 M events/sec` on the
  match path is interesting: matching is slightly *faster* than no-match because
  the early exit from the rule walk avoids the resolver calls the no-match path
  still has to make.
- **Eval cost is `O(n_rules)` per event.** A production config of 10–100 rules
  will scale linearly: 100 rules on the no-match path is ~12–13 µs/event
  (~80 K events/sec), which is still well within the project's per-stage budget.

The match path is faster than the no-match path because the no-match path still
has to call the resolver for every field each expression references, while the
match path exits as soon as a rule fires. The benchmarks use a 3-rule config
where the first rule does not match in either case, so the no-match path runs
the full resolver chain while the match path exits on the second rule.

## 12. Testing

The WAF plugin is covered by four test files, each with a distinct surface:

- **`processor_test.go`** — unit tests for `WafProcessor`:
  match/no-match path, `drop`/`tag`/`pass` actions, concurrent `Process` calls,
  fail-fast on bad expression at `NewWafProcessor` time, context cancellation
  honored before any rule evaluation, empty config passes through.

- **`resolver_test.go`** — table-driven field resolution for all 12 `http.*`
  fields: each `Manifest.Produces` entry has a "populated" and "empty" case;
  nil event, wrong namespace, and `*threat.ThreatEvent` payload are covered as
  boundary cases; malformed IP strings return `(Value{}, false)` (never
  `0.0.0.0`).

- **`ruleset_test.go`** — `BuildScheme` and `NewRuleSetFromConfig` paths: the
  builder's `Err()` channel is exercised with duplicate / unknown-type
  registrations; bad expression compile paths (`Add` returning the
  parser/compiler error tagged with the stage).

- **`integration_test.go`** — end-to-end coverage (Flow 001 Task H5): nginx
  Combined Log Format and nginx JSON log input via `parser.Parse` → WAF →
  verdict; `in` operator with a CIDR list (RFC 4632 / IPv4 membership
  semantics); `matches` operator with an RE2 pattern against
  `http.user_agent`; fail-fast contract on a bad expression; the throughput
  benchmarks quoted in [Performance characteristics](#11-performance-characteristics).

Run everything:

```bash
go test -race ./pkg/processorplugins/waf/...
```

Run only the benchmarks:

```bash
go test -bench=BenchmarkWafProcessor -benchmem -run=^$ ./pkg/processorplugins/waf/...
```

## 13. Changelog

| Date | Tasks | Notes |
|------|-------|-------|
| 2026-06-29 | H1–H5 | Initial implementation: Manifest, `HttpResolver`, `RuleSet` wiring, `Process` with action dispatch, integration tests. |
| 2026-06-29 | H6–H11 | Two-pass evaluation (`passRules`/`gateRules`); `tag:<label>` syntax with `TagWeights`; `ScoreFunc` + `DropScore` + `clientIP`; `processors:` wire-up in pipeline with backward-compat nil-gate. |
