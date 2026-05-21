# Technical Debt

Tracked items of known technical debt. Each item includes origin flow,
severity, description, and proposed resolution.

---

## Format

```
### [ID] Short title
- **Flow:** #NNN — flow name
- **Severity:** low / medium / high
- **Area:** package or subsystem
- **Problem:** what is wrong and why it matters
- **Resolution:** proposed fix
- **Status:** open / in progress / resolved (Flow #NNN)
```

---

## Open

### [002] main.go should move to cmd/arxsentinel/main.go

- **Flow:** #027 — Repo Cleanup & Structure
- **Severity:** low
- **Area:** project layout, goreleaser, CI, Dockerfiles
- **Problem:** main.go in root is non-standard for Go projects with tooling. Standard layout
  expects cmd/<binary>/main.go. Deferred due to high coordination cost (6+ files to update).
- **Resolution:** Dedicated flow — update goreleaser, Dockerfiles, install.sh, packaging,
  CI workflow, all documentation references in one atomic set of commits.
- **Status:** resolved (Flow #028)

---

## Resolved

### [001] BadBotDetector: bbolt file opened per-stream, not shared as singleton

- **Flow:** #024 — BadBot Community Blocklist Detector
- **Severity:** medium
- **Area:** `internal/core/detector/badbot.go`, `main.go`
- **Problem:** `buildDetectors()` is called once per log stream. Each call creates a new
  `BadBotDetector` instance via `newBadBotDetector()`, which in turn calls `newPatternStore()`.
  If `storage` is set to a bbolt path, every stream tries to open the same `.db` file.
  bbolt uses a file-level write lock — only the first opener succeeds; subsequent streams
  silently fall back to `MemoryStore` and fetch patterns independently over the network.
  This means: redundant HTTP fetches per stream, inconsistent memory usage, and silent
  degradation that is hard to diagnose.
- **Resolution:** Make `BadBotDetector` (or at minimum its `PatternStore` + automata pair)
  a package-level singleton, initialized once and shared across all streams via `sync.Once`.
  Alternatively, pass a shared detector instance through `buildDetectors()` instead of
  constructing it inside the factory.
- **Status:** resolved (Flow #025) — `blocklist.Manager` is created once in `main()` and
  passed to all streams via `SharedResources`. `BadBotDetector` is now a thin wrapper over
  `Manager.Match()`. A single bbolt file is opened by the Manager; no per-stream duplication.
