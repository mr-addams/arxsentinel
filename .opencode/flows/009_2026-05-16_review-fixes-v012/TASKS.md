# Flow #9 — Review Fixes v0.1.2

**Started:** 2026-05-16  
**Closed:** 2026-05-16  
**Status:** ✅ Closed — коммит 209efc0

## Goal

Реализовать исправления по полному ревью nginx-sentinel v0.1.2:
5 предупреждений (🟡) + 2 рекомендации (🟢 R1, R2).
Нет новых зависимостей, нет изменений публичных интерфейсов.

---

## Tasks

### Группа A — Быстрые исправления

- ✅ **A.1** — W2: удалить uppercase-дубликаты из `scannerPatterns` и `grabberPatterns`
  - Файл: `internal/core/detector/useragent.go`
  - Убрать: `"Nikto"`, `"ZGrab"`, `"DirBuster"`, `"WFuzz"`, `"FFUF"`, `"Hydra"`, `"Medusa"`, `"BurpSuite"`, `"Scrapy"`
  - Decision 2

- ✅ **A.2** — W4: SIGHUP relay — дренаж `sigHUP` при `ctx.Done()`
  - Файл: `main.go`
  - В `case <-ctx.Done()`: добавить `signal.Stop(sigHUP)` + цикл дренажа
  - Decision 4

  🚀 **Push point A** — быстрые исправления

### Группа B — Защита от аномалий

- ✅ **B.1** — W5: ограничение длины строки в `TailReader`
  - Файл: `internal/sys/utils/tail.go`
  - Добавить константу `maxLineSize = 64 * 1024`
  - Заменить `bufio.NewReader(f)` → `bufio.NewReaderSize(f, maxLineSize)` во всех местах создания reader
  - Decision 5

### Группа C — Оптимизация производительности

- ✅ **C.1** — W1: кэш `RecentPaths()` через dirty-флаг
  - Файл: `internal/core/state/tracker.go`
  - Добавить в `IPState`: `pathCache []string`, `pathDirty bool`
  - В `Update()` после записи в ring buffer: `st.pathDirty = true`
  - В `RecentPaths()`: вернуть `pathCache` если `!pathDirty`, иначе — перестроить, кэшировать, сбросить флаг
  - Decision 1

  🚀 **Push point B** — защита + оптимизация

### Группа D — CI / тестирование

- ✅ **D.1** — W3: синтетический E2E-лог для CI
  - Создать `testdata/synthetic.access.log` (15–20 строк nginx combined format)
    - IP `10.0.0.1`: много 404-ов + scanner UA → должен дать THREAT
    - IP `10.0.0.2`: легитимный трафик → не должен попасть в threat-log
  - Добавить тест `TestE2ESynthetic` в `e2e_test.go` (build tag `e2e`)
    - Не требует локальных файлов из `.gitignore`
    - Проверяет: наличие `THREAT 10.0.0.1`, формат failregex, отсутствие `10.0.0.2` в threat-log
  - Decision 3

  🚀 **Push point C** — E2E в CI работает

### Группа E — Рефакторинг

- ✅ **E.1** — R1: factory-паттерн для `buildDetectors`
  - Файл: `main.go`
  - Ввести тип `detectorFactory func(*config.Config) detector.Detector`
  - Заменить 7 if-блоков на `[]detectorFactory{...}` + цикл с фильтрацией `nil`
  - Decision 6

- ✅ **E.2** — R2: `PipelineContext` struct для `processLine`
  - Файл: `main.go`
  - Определить struct с полями: `Matcher`, `Verifier`, `Tracker`, `Scorer`, `ThreatLogger`, `Config`
  - Обновить сигнатуру `processLine` и все точки вызова
  - `PipelineContext` пересоздаётся при SIGHUP reload
  - Decision 7

  🚀 **Push point D** — рефакторинг завершён, финальный push

---

## Push Points

🚀 **A** — W2 + W4 исправлены и протестированы  
🚀 **B** — W5 + W1 исправлены и протестированы  
🚀 **C** — W3: синтетический E2E в git, CI проходит  
🚀 **D** — R1 + R2 завершены, финальный `go test ./... -tags e2e` чист  

---

## Verification

```bash
go build ./...
go test ./...
go test -tags e2e ./...
go vet ./...
```
