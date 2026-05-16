# Architectural Decisions — Flow #9 — Review Fixes v0.1.2

## Context

Полное ревью nginx-sentinel v0.1.2 (67 файлов, ~3500 строк) выявило:
- **0 критических** проблем
- **5 предупреждений** (🟡) — рекомендуется исправить
- **5 рекомендаций** (🟢) — 2 включены в скоуп, 3 в roadmap v0.2+

Все изменения изолированы: нет затронутых публичных интерфейсов, нет новых зависимостей.

---

## Decision 1 — Кэш `RecentPaths()` через dirty-флаг

**Date:** 2026-05-16  
**Decision:** Добавить в `IPState` поля `pathCache []string` и `pathDirty bool`.
В `Update()` после записи в ring buffer выставлять `pathDirty = true`.
В `RecentPaths()` возвращать `pathCache` при `!pathDirty`, иначе — перестраивать и сбрасывать флаг.

**Rationale:**
- `CrawlerDetector` вызывает `RecentPaths()` на каждую строку лога
- Без кэша — `make + copy` ~1.3 KB аллокаций/строку при ring buffer 64 элемента
- При 100k rps экономия ~130 MB/s аллокаций → снижение GC-давления
- Dirty-флаг — минимальное изменение, не ломает логику ring buffer

**Consequences:**
- `IPState` вырастет на 1 slice + 1 bool (~незначительно к ~1.2 KB)
- `RecentPaths()` больше не аллоцирует при кэш-хите
- Изменения только в `internal/core/state/tracker.go`

---

## Decision 2 — Удаление дубликатов регистра из UA-паттернов

**Date:** 2026-05-16  
**Decision:** Удалить uppercase-варианты из `scannerPatterns` и `grabberPatterns`,
оставить только lowercase (компаратор `strings.ToLower` с обеих сторон делает их идентичными).

**Rationale:**
- `strings.ToLower(ua)` + `strings.ToLower(p)` означает что `"Nikto"` и `"nikto"` дают одинаковый результат
- Дубли — мёртвый код, увеличивают размер slice и время итерации

**Consequences:**
- Поведение детектора не изменится (семантически эквивалентно)
- Паттерны с нижним регистром остаются, uppercase-дубли удаляются
- Паттерны с символами (`"Wget/"`, `"curl/"`, `"Java/"`) — не дубликаты, не трогаем

---

## Decision 3 — Синтетический E2E-лог в git для CI

**Date:** 2026-05-16  
**Decision:** Создать `testdata/synthetic.access.log` (15–20 строк) и тест `TestE2ESynthetic`
с build tag `e2e`. Существующий тест с `.reference/example.access.log` не трогать.

**Rationale:**
- `.reference/example.access.log` в `.gitignore` → E2E-тест в CI всегда пропускается
- Синтетический лог: минимальный набор строк, воспроизводящий ключевые сценарии
  (scanner UA + 404-ы → THREAT; легитимный трафик → не в threat-log)
- Build tag `e2e` сохраняется — оба теста запускаются вместе с `-tags e2e`

**Consequences:**
- `testdata/` добавляется в git, CI получает рабочий E2E-тест
- Синтетический лог проверяет: формат threat-строки, failregex, порог THREAT

---

## Decision 4 — SIGHUP relay: явный дренаж канала при shutdown

**Date:** 2026-05-16  
**Decision:** В `case <-ctx.Done()` ветке SIGHUP-горутины добавить `signal.Stop(sigHUP)`
и дренаж `for len(sigHUP) > 0 { <-sigHUP }` перед `return`.

**Rationale:**
- Текущий код: `defer signal.Stop(sigHUP)` только в main, но горутина может не успеть
  дочитать сигнал до завершения main
- При race condition `signal.Notify` может попытаться записать в полный канал (size 1)
- Дренаж в горутине — детерминированная очистка без гонок
- Двойной `signal.Stop` безопасен (идемпотентен)

**Consequences:**
- Изменение в 3 строки в `main.go`
- Устраняет потенциальную блокировку при завершении под нагрузкой

---

## Decision 5 — Ограничение длины строки в TailReader через NewReaderSize

**Date:** 2026-05-16  
**Decision:** Заменить `bufio.NewReader(f)` на `bufio.NewReaderSize(f, maxLineSize)`
где `maxLineSize = 64 * 1024` (64 KB). Константа определяется в том же файле.

**Rationale:**
- `ReadString('\n')` без ограничения аллоцирует буфер произвольной длины
- Атака через аномально длинный URL → большая разовая аллокация
- 64 KB перекрывает любой реальный nginx access.log с запасом
- `NewReaderSize` — стандартный Go-паттерн для ограничения буфера

**Consequences:**
- Строки длиннее 64 KB будут разбиты на части (каждая часть без `\n`) →
  парсер `Parse()` вернёт `(nil, false)` на неполной строке — штатная обработка

---

## Decision 6 — Factory-паттерн для buildDetectors

**Date:** 2026-05-16  
**Decision:** Заменить 7 независимых if-блоков в `buildDetectors` на slice
factory-функций типа `func(*config.Config) detector.Detector`.
Функция возвращает `nil` если детектор отключён — тогда не добавляется в результат.

**Rationale:**
- Текущие 7 if-блоков функционально одинаковы: проверить Enabled → создать → append
- При добавлении нового детектора нужно добавить if-блок (риск забыть)
- Factory-slice: добавление нового детектора = одна строка в slice

**Consequences:**
- Поведение не меняется: те же детекторы, та же логика включения
- Упрощает добавление детекторов в будущем (roadmap v0.2+)
- Изменения только в `main.go`

---

## Decision 7 — PipelineContext struct для processLine

**Date:** 2026-05-16  
**Decision:** Сгруппировать долгоживущие зависимости `processLine` (6 из 9 параметров)
в struct `PipelineContext`. Короткоживущие `ctx` и `entry` остаются параметрами.

**Rationale:**
- 9 параметров — многовато; 6 из них — компоненты, которые меняются только при SIGHUP
- `PipelineContext` пересоздаётся при reload вместо того чтобы передавать 6 переменных
- Функция не экспортируется → изменение сигнатуры локально в `main.go`

**Consequences:**
- `processLine` меняет сигнатуру: было 9 параметров, стало 3
- `PipelineContext` пересоздаётся при каждом SIGHUP reload (как раньше отдельные переменные)
- Все вызовы `processLine` в `main.go` обновляются

---

## Out of Scope

- Prometheus `/metrics` endpoint — roadmap v0.2+
- `ip_ranges` HTTP-клиент (Facebook/Twitter/Telegram) — roadmap v0.2+
- `rdns_ipjson` через Google JSON API — roadmap v0.2+
