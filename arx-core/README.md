# arx-core — Core-модуль TelemetryCore

Это подмодуль ядра `TelemetryCore` (Phase 2) внутри монорепо `arxsentinel`.

- **Module path:** `github.com/mr-addams/arx-core`
- **Go version:** `1.26`
- **Где живёт:** в поддиректории `arx-core/` того же git-репозитория `arxsentinel`.
  Не отдельный репозиторий, не публикуется в Go module proxy — это **local-only**
  модуль, резолвится через `go.work` в корне репо.

## Почему в монорепо, а не в отдельном репо

PoC-решение Flow 078. Обоснование — в `.opencode/flows/078_2026-06-22_gowork-logger-poc/DECISIONS.md`
(Decision 2). Главные причины:

- Проще откатить (одна поддиректория, один коммит) пока PoC не валидирован.
- ADR-002 из Phase 2 зафиксировал, что `arx-core` живёт в репо `arxsentinel`.
- Решение о реальной семантической версии и возможном вынесении в отдельный
  репо — **post-PoC** вопрос. Пока placeholder `v0.0.0-00010101000000-000000000000`.

## Пакеты

### `pkg/logger` (первый Core-пакет, leaf, stdlib-only)

Generic structured logging для всего проекта.

- **Boundary:** ADR-002 классифицирует `logger` как **Core** (нет зависимостей
  на `Product`-слой; stdlib + минимальный interface `Logger`).
- **Публичный API:** интерфейс `Logger` с методом `Log(tag, msg, level string)`,
  `NopLogger`, константы `Level*`. Подробнее — `pkg/logger/README.md`.
- **Зависимости:** **0** — только Go stdlib.
- **Импортируется из:** 19 файлов внутри `arxsentinel` (Core + Product слои).
  Полный список — в Flow 078 `TASKS.md`, Tasks 3.1–3.19.

## Boundary-правила (ADR-002)

Файлы в `arx-core/` **не должны** импортировать ничего из верхнего слоя
`arxsentinel` (`pkg/...`, `internal/...` основного репо). Это обеспечивает
направленность зависимостей строго вниз — `arxsentinel` → `arx-core`,
но не наоборот.

Boundary ADR-002 фиксируется в архитектурных заметках проекта
(см. `.opencode/config/opencode/architecture/overview.md` и файлы в
`.opencode/config/opencode/architecture/adr/`).

## Локальная разработка

```bash
# Корень монорепо уже содержит go.work, который подхватывает arx-core/.
# Никаких дополнительных шагов инициализации не требуется.
go build ./...
go test -race -count=1 ./...
```

Release-конфигурация (`goreleaser`, `dev-release.yml`, `release.yml`)
поддерживается через `go.work`; corner-cases отрабатываются в Flow 078
gate-этапе.

## Что НЕ входит в этот модуль сейчас

- ~14 других Core-пакетов из ADR-002 (`ncs`, `executor/registry`,
  `executor/queue`, `sys/utils`, …) — переносятся в **последующих флоуах**
  после успешного PoC.
- Реальная семантическая версия (`v0.0.1`+) — отложенное post-PoC решение.
- Публикация в module proxy — **никогда**, модуль локальный.