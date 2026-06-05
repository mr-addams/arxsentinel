# `pkg/detector` — Detector Registry and Built-in Detectors

The central registry and home of the eight built-in HTTP detectors in
ArxSentinel. Each detector self-registers through `init()`, and the
pipeline obtains a live instance via `Build(name, cfg, shared)`.
Detectors are **stateless** — all per-IP state lives behind the
`plugin.IPView` interface the pipeline threads through.

The package depends only on `pkg/plugin` and `pkg/execplugin`. It does
**not** import anything from `internal/`, so external developers can
embed it as a standalone library.

## Module Layout

```
pkg/detector/
├── registry.go      # Registry, SharedResources, Matcher, Factory, DetectorConfig
├── params.go        # Type-safe params helpers + noopMatcher
├── manifest.go      # PluginID constants
├── probe.go bruteforce.go crawler.go noasset.go
├── rate.go useragent.go badbot.go overflow.go
└── registry_test.go # External test package: 13 tests
```

Twelve files, ~1747 lines. Eight active detectors plus one disabled
stub returned by the `rate` factory when its window or threshold is
non-positive.

## Architectural Role

`pkg/detector` sits between YAML configuration and the pipeline
runtime. `main.go` converts the public `config.DetectorConfig` into
the package-local `DetectorConfig` and hands it to `Build`. The
returned `plugin.Detector` is then driven per request by the
pipeline:

```
config.DetectorConfig ─► detector.DetectorConfig ─► Build(name, cfg, shared)
                                                           │
                                                           ▼
                                                  plugin.Detector
                                                           │
                                                           ▼
                                          Detect(IPView, *LogEntry) → DetectResult
```

A new detector is a new file plus a single `Register` call. There is
no central map.

## Core Types (`registry.go`)

```go
type DetectorConfig struct {
    Enabled bool
    Params  map[string]interface{}  // yaml:",inline"
    Exec    string
}

type Matcher interface {
    Match(value string) (listName string, ok bool)
}

type SharedResources interface {
    Blocklist() Matcher
}

type Factory func(cfg DetectorConfig, shared SharedResources) (plugin.Detector, error)
```

- `Enabled == false` → `Build` returns `(nil, nil)`.
- `Params` is everything that is neither `enabled` nor `exec`.
  Detectors extract typed values via the helpers in `params.go`.
- `Matcher` is **duck-typed** — the concrete blocklist manager in
  `internal/core/blocklist` satisfies it implicitly through Go's
  structural interface model. There is no explicit import.
- `badbot` is the only consumer of `SharedResources`.

### Registry API

```go
func Register(name string, f Factory)
func Build(name string, cfg DetectorConfig, shared SharedResources) (plugin.Detector, error)
func Names() []string
```

- `Register` **panics on duplicate names**; a duplicate is a
  programming error caught at process start.
- `Build` returns `(nil, nil)` for disabled detectors, a real detector
  for any registered name, an exec-plugin wrapper for unknown names
  with `cfg.Exec != ""`, or an error otherwise.
- `Names` returns the registered names, sorted.

### Exec Fallback

When a name is not registered here but `cfg.Exec` is set, `Build`
delegates to `pkg/execplugin` and returns a wrapper that shells out to
the configured binary per `Detect` call. This lets operators ship a
custom detector in any language without recompiling the agent.

### Thread Safety

The factory map is guarded by a `sync.RWMutex`. `Names()` and `Build()`
take the read lock, `Register()` takes the write lock. `Register` is
intended to run from `init()`; the lock is there to keep the race
detector quiet for any future dynamic-registration path.

## The `plugin.Detector` Contract

```go
type Detector interface {
    Name() string
    Detect(sv IPView, entry *LogEntry) DetectResult
    Manifest() Manifest
}
```

`IPView` exposes per-IP counters: `GetTotalRequests()`,
`GetRequests404()`, `RecentPaths()`, `ApproxRate(window)`. Detectors
read them; they do not mutate them. `DetectResult` carries
`Score int`, `Module string`, `Reason string`; `Score == 0` means
"clean".

## Built-in Detector Reference

| #  | Reg. name  | PluginID    | Category        | Tags                                       |
|----|------------|-------------|-----------------|--------------------------------------------|
| 1  | `probe`      | `probe`       | path-based      | http, path-based, sensitive-paths          |
| 2  | `rate`       | `rate`        | rate-based      | http, rate-based, dos                      |
| 3  | `bruteforce` | `bruteforce`  | rate-based      | http, rate-based, bruteforce               |
| 4  | `crawler`    | `crawler`     | path-based      | http, path-based, sequential               |
| 5  | `noasset`    | `noasset`     | path-based      | http, path-based, no-asset                 |
| 6  | `ua`         | `useragent`   | signature-based | http, signature-based, user-agent         |
| 7  | `badbot`     | `badbot`      | blocklist-based | http, blocklist-based, bad-bot             |
| 8  | `overflow`   | `overflow`    | payload-based   | http, payload-based, overflow              |

**PluginID caveat.** For seven of the eight detectors the PluginID
equals the registration name. The exception is the UA detector:
registration name is **`ua`**, PluginID is **`useragent`**.

---

### `probe` — sensitive path probing

Exact match (O(1) `map[string]struct{}` lookup) for static paths
(`.env`, `wp-config.php`); prefix match for paths ending in `/` in
the config (e.g. `/wp-admin/`, `/actuator/`). `defaultProbePaths()`
returns both kinds; the builder splits them at construction.

| Key     | Type     | Default               | Description                          |
|---------|----------|-----------------------|--------------------------------------|
| `score` | int      | 25                    | Score on a hit.                      |
| `paths` | []string | (large built-in list) | Exact paths and `/`-terminated prefixes. |

- **Detect input:** `entry.Path` only.
- **Reason:** `probe:<matched-path>`.

### `rate` — requests-per-second threshold

`thresholdRPS = threshold / window.Seconds()` is precomputed once in
the factory. The hot path is a single float64 compare between
`ApproxRate(window)` and `thresholdRPS`.

| Key         | Type     | Default | Description                              |
|-------------|----------|---------|------------------------------------------|
| `threshold` | int      | 100     | Total requests allowed over the window.  |
| `window`    | duration | 60s     | Sliding window for `ApproxRate`.         |
| `score`     | int      | 25      | Score on a hit.                          |

- **Detect input:** `IPView.ApproxRate(window)`.
- **Reason:** `rate:rps=<value>`.
- **Disabled stub.** When `window <= 0` or `threshold <= 0`, the
  factory returns a `disabledRateDetector` — a **no-op
  implementation, not `(nil, nil)`**. It still has `Name() == "rate"`
  and always returns `Score == 0`. The pipeline never sees nil for
  the `rate` name, only a permanently silent one.

### `bruteforce` — 404 ratio

`ratio = GetRequests404() / GetTotalRequests()`. Guard: if `total <
min_requests` the detector does **not** fire — early-stage traffic is
not representative. Otherwise fire when `ratio >= ratio_threshold`.

| Key                | Type  | Default | Description                                    |
|--------------------|-------|---------|------------------------------------------------|
| `min_requests`     | int   | 10      | Minimum total requests before scoring.         |
| `ratio_threshold`  | float | 0.6     | 404 ratio above which the IP is flagged.       |
| `score`            | int   | 30      | Score on a hit.                                |

- **Detect input:** `IPView.GetTotalRequests()`, `IPView.GetRequests404()`.
- **Reason:** `bruteforce:404=<pct>%(<hits>/<total>)`.

### `crawler` — sequential numeric paths

A regex `^(.*/|/)(\d+)/?$` extracts the prefix and numeric suffix
from each path in `RecentPaths()`. Paths are grouped by prefix,
deduplicated, sorted numerically, and scanned for monotonic runs of
length ≥ `min_sequential`.

| Key              | Type | Default | Description                                  |
|------------------|------|---------|----------------------------------------------|
| `min_sequential` | int  | 5       | Minimum length of a numeric run to trigger.  |
| `score`          | int  | 20      | Score on a hit.                              |

- **Detect input:** `IPView.RecentPaths()`.
- **Reason:** `crawler:seq=<prefix>*<n>`.
- **Bounded by the 64-path ring buffer** in `state.IPState`.

### `noasset` — pages without assets

For each path, `path.Ext()` (forward-slash semantics, query string
stripped defensively) yields an extension. Extensions are looked up
in an `extSet` (`map[string]struct{}`, lowercased) for O(1)
membership. Tracks page and asset counts; fires when pages ≥
`min_page_requests` and asset ratio < `asset_ratio_threshold`.

| Key                     | Type      | Default             | Description                                 |
|-------------------------|-----------|---------------------|---------------------------------------------|
| `min_page_requests`     | int       | 3                   | Minimum page hits before scoring.           |
| `asset_ratio_threshold` | float     | 0.1                 | Asset/page ratio below which the IP fires.  |
| `score`                 | int       | 20                  | Score on a hit.                             |
| `asset_extensions`      | []string  | (built-in defaults) | Extensions considered static assets.        |

- **Detect input:** `IPView.RecentPaths()`.
- **Reason:** `noasset:pages=<n>,assets=<n>,ratio=<pct>%`.
- **Bounded by the 64-path ring buffer.**

### `ua` (PluginID: `useragent`) — User-Agent signature

UA is checked in a fixed order; the first match wins:

1. Empty UA (`""` or `"-"` — nginx placeholder) → `empty_ua_score`.
2. Built-in scanner patterns → `scanner_score`.
3. Built-in grabber patterns → `grabber_score`.
4. Built-in automation patterns → `automation_score`.

The UA is lowercased once per call. The built-in patterns are
**hard-coded** (19 scanner, 11 grabber, 10+ automation). Extra
patterns from `Params` are **appended** — they cannot replace or
remove the built-in entries through YAML.

| Key                         | Type     | Default | Description                              |
|-----------------------------|----------|---------|------------------------------------------|
| `scanner_score`             | int      | 40      | Score for scanner-pattern matches.       |
| `grabber_score`             | int      | 20      | Score for grabber-pattern matches.       |
| `automation_score`          | int      | 15      | Score for automation-tool matches.       |
| `empty_ua_score`            | int      | 30      | Score for empty / placeholder UAs.       |
| `extra_scanner_patterns`    | []string | —       | Additional scanner regexes (appended).   |
| `extra_grabber_patterns`    | []string | —       | Additional grabber regexes (appended).   |
| `extra_automation_patterns` | []string | —       | Additional automation regexes (appended).|

- **Detect input:** `entry.UserAgent` only.
- **Reason:** `ua:scanner:<p>`, `ua:grabber:<p>`, `ua:automation:<p>`,
  or `ua:empty`.

### `badbot` — blocklist match (UA and Referer)

Looks up `entry.UserAgent` and/or `entry.Referer` in a `Matcher`
pulled from `SharedResources.Blocklist()`. The blocklist list names
are hard-coded: **`"badbot-ua"`** for UA, **`"badbot-ref"`** for
Referer. If your YAML names differ, the detector silently finds no
matches — this is documented behaviour, not a bug.

**Graceful degradation.** When `shared == nil` or
`shared.Blocklist() == nil`, the detector switches to a `noopMatcher{}`
that never matches. The detector itself stays non-nil.

| Key              | Type | Default | Description                          |
|------------------|------|---------|--------------------------------------|
| `check_ua`       | bool | true    | Whether to match the User-Agent.     |
| `check_referrer` | bool | false   | Whether to match the Referer.        |
| `score`          | int  | 60      | Score on a hit.                      |

- **Detect input:** `entry.UserAgent`, `entry.Referer`.
- **Reason:** `ua=<matched-list-name>`.

### `overflow` — URL length and WAF-bypass keywords

The URL is reconstructed as `Path + "?" + Query` (the `?` is omitted
when `Query` is empty). The detector fires when **either** condition
holds:

1. The URL byte length exceeds `max_url_length`.
2. Any `suspicious_params` key appears in the URL.

`len()` is a byte count — correct for ASCII URLs (RFC 3986) and
consistent with how reverse proxies measure URL length.
Percent-encoding does not shrink the count. The built-in
`suspicious_params` are lowercased once at construction; the URL is
matched case-insensitively.

| Key                 | Type     | Default            | Description                          |
|---------------------|----------|--------------------|--------------------------------------|
| `max_url_length`    | int      | 2048               | Maximum accepted URL byte length.    |
| `suspicious_params` | []string | (7 built-in keys)  | Parameter names that trigger a hit.  |
| `score`             | int      | 30                 | Score on a hit.                      |

- **Detect input:** `entry.Path`, `entry.Query`.
- **Reason:** `overflow:url_len=<n>` or `overflow:waf_bypass=<key>`.

---

## Params Helpers (`params.go`)

The `Params` map is a `map[string]interface{}` after YAML parsing —
every value is untyped. Detractors extract typed values through the
helpers in `params.go`. **All helpers are silent on error**: a
missing key or a wrong-typed value yields the documented default,
never a panic.

| Helper                              | Accepts                | Default on error |
|-------------------------------------|------------------------|------------------|
| `getInt(params, key, default)`      | int / float64          | `default`        |
| `getDuration(params, key, default)` | string / int / float64 | `default`        |
| `getString(params, key, default)`   | string                 | `default`        |
| `getStrings(params, key, default)`  | []interface{}          | `default`        |
| `getFloat(params, key, default)`    | int / float64          | `default`        |
| `getBool(params, key, default)`     | bool                   | `default`        |

The silent default is intentional: a misconfigured detector should
not crash the agent. Operators are expected to read detector output
and adjust the YAML. The same file also defines `noopMatcher{}`, a
zero-value matcher that always returns `ok == false` — used by
`badbot` when `SharedResources` is absent.

## SharedResources and Dependency Injection

`SharedResources` is the only channel through which `pkg/detector`
sees runtime state beyond the current `LogEntry`. The pipeline owns
the concrete value and passes it to `Build`; detectors that do not
need it simply ignore it. The adapter that turns a concrete blocklist
manager into a `SharedResources` typically lives in `internal/app` —
it does not need to be in this package, because the only contract
enforced here is the `SharedResources` interface itself.

## Testing

Tests live in `registry_test.go` under `package detector_test` — the
**external test package**. Tests exercise the registry exclusively
through its public surface, which is the surface external consumers
will use.

The test architecture is two-layered:

- **Registry unit tests** — `Names()`, `Build` with disabled config,
  `Build` with unknown name.
- **Smoke tests per detector** — one test per detector, each building
  it through the registry with a known config and a small scenario,
  asserting on `DetectResult`.

Stubs: `stubView` (IPView), `stubMatcher` (Matcher), `stubShared`
(SharedResources). The thirteen tests cover: registry basics,
`TestProbeDetector_ViaRegistry` (`/.env` fires), `TestRateDetector_*`
(high/low/disabled window), `TestBruteforceDetector_ViaRegistry`
(90% 404), `TestCrawlerDetector_ViaRegistry` (3 sequential),
`TestNoAssetDetector_ViaRegistry` (pages only), `TestUADetector_*`
(empty / `-` / Nuclei / Mozilla), `TestBadBotDetector_ViaRegistry` /
`TestBadBotDetector_NilShared` (mock matcher + nil-shared fallback),
`TestOverflowDetector_ViaRegistry` (long URL / WAF bypass / clean).

When adding a new detector, add one smoke test that builds it
through the registry, feeds a small `LogEntry` plus a `stubView`, and
asserts on the `DetectResult`. A detector without a smoke test is a
detector whose semantics are unverified.

## Configuration

`pkg/detector` holds no YAML; the configuration surface lives in
`config.go` and `PipelineRuntimeConfig`. There are two levels:

1. **Global `detectors:`** — explicit fields for `probe`,
   `bruteforce`, `crawler`, `noasset`, `rate`, `useragent`, `badbot`,
   and `overflow`. Defaults applied to every pipeline.
2. **Per-pipeline `pipelines[].detectors:`** — a
   `map[string]DetectorConfig` keyed by registration name. Overrides
   the global config for that pipeline. When nil, the pipeline uses
   every registered detector with global defaults.

### Exempting a Detector per Entry

A pipeline can carry an `exempt_detectors: ["noasset", …]` list in
its `PipelineRuntimeConfig`. Matching entries skip that detector. The
list is interpreted as registration names (`"ua"`, **not**
`"useragent"`).

### Blocklist Configuration

The global `blocklist:` section declares the lists `badbot` reads
from. The list names `"badbot-ua"` and `"badbot-ref"` are the keys
`badbot` looks up. Renaming them in YAML yields silent no-matches.

## Constraints and Invariants

Load-bearing rules of the package — do not break:

- **No `internal/` imports.** `pkg/detector` is a public library.
- **No detector depends on another.** Shared helpers live in
  `params.go` only; detector files do not import each other.
- **Registration is by `init()` only.** No central map, no factory
  list. Adding a detector is a new file plus a single `Register`
  call.
- **`rate` returns a no-op, not nil.** The pipeline may assume the
  result of `Build("rate", …)` is non-nil whenever `Enabled` is true.
- **`ua` PluginID is `useragent`.** Plugin metadata is not
  interchangeable with the registration name.
- **Built-in UA patterns are immutable from YAML.** Only `extra_*`
  patterns are user-controlled.
- **`RecentPaths()` is bounded at 64 paths.** This is a property of
  `state.IPState`; detectors that depend on it (`crawler`, `noasset`)
  inherit the cap.
- **Score is untyped.** Each detector picks its own scale. The
  pipeline scorer is the only place that aggregates scores into a
  decision.
- **Blocklist names are hard-coded** in `badbot` as `"badbot-ua"` and
  `"badbot-ref"`.
