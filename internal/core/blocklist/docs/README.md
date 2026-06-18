# Blocklist Manager — внутреннее устройство

## Overview

Пакет `blocklist` реализует централизованное управление блоклистами (стоп-словами,
списками плохих IP/UA/referrer и т.д.) для детекторов ArxSentinel.

**Ключевые принципы:**
- Детекторы не знают откуда берутся паттерны — они вызывают `Match()` / `MatchResult()`
- Менеджер — единая точка владения всеми блоклистами (singleton, создаётся в `main()`)
- Автоматы Aho-Corasick перестраиваются при каждом обновлении из upstream, без блокировки чтения

## Файлы и их ответственность

| Файл | Назначение |
|------|------------|
| `manager.go` | Config, Manager struct, lifecycle (New/Update/Close), Match, bbolt persistence |
| `manager_test.go` | Тесты Manager (без network — с `http.NewServeMux`/`httptest`) |
| `parser.go` | Парсеры форматов `plain_text`, `nginx_map` |
| `parser_test.go` | Тесты парсеров |

## Goroutine Lifecycle

Каждый именованный блоклист (`ListConfig`) имеет собственный goroutine с внутренним
ticker'ом заданного `refresh_interval`. Схема:

```
NewManager(ctx, cfg)
  └─ startList(ctx, lc)  — для каждой включённой (enabled) записи списка
       ├─ loadFromBolt()  — быстрый старт: загрузить сохранённые паттерны
       ├─ fetchAndUpdate() — первая загрузка из upstream
       └─ ticker.C ─┬─ fetchAndUpdate()  — периодическое обновление
                     └─ listCtx.Done()    — остановка при Update() или Close()

Update(ctx, cfg)
  ├─ cancel() каждого listState → все goroutine завершаются
  └─ startList() для каждой записи в новом конфиге

Close()
  └─ cancel() каждого listState → все goroutine завершаются
```

### Жизненный цикл одной goroutine:

1. **Fast path** — загрузка из bbolt (если настроен). Автомат доступен немедленно
   при старте, до первого network fetch.
2. **Первый fetch** — `fetchAndUpdate()` загружает все источники, парсит, строит автомат.
3. **Ticker** — каждый `refresh_interval` повторяет fetch.
4. **Отмена** — при `Update()` или `Close()` общий сигнал `cancel()` завершает goroutine.

## Ошибки: что происходит, когда все источники упали

Ключевое поведение: **при полном отказе всех источников существующий автомат
НЕ ТРОГАЕТСЯ.**

```go
if !anyLoaded {
    utils.Log("BLOCKLIST", "all sources failed — keeping previous patterns", "warn")
    return
}
```

### Сценарии:

| Ситуация | Поведение |
|----------|-----------|
| Один источник упал, другой жив | Маска с данными от живого источника; упавший логируется как `warn` и пропускается |
| Все источники упали | Существующий автомат остаётся (детекторы продолжают работать с предыдущими паттернами) |
| Первый запуск и все источники упали | Автомат = nil → `Match()` возвращает `false` (graceful degradation) |
| Источник вернул пустой ответ | Пробуется fallback-парсер (nginx_map если plain_text дал 0) |
| Fetch превысил 30s | HTTP-клиент прерывает запрос; источник помечается как недоступный |

### Причины ошибок fetch:

- Таймаут соединения (HTTP-клиент имеет `Timeout: 30s`)
- HTTP статус не 200
- Ошибка парсинга (неверный формат)
- Context cancelled (при `Update()` или `Close()`)

## Thread Safety

```
Match / MatchResult:  RLock Manager → RLock listState → поиск → RUnlock listState → RUnlock Manager
fetchAndUpdate:       RLock Manager (read db) → [build automaton] → state.setMatcher() → Lock listState (write)
Update / Close:       Lock Manager (write) → cancel + replace lists → Unlock Manager
```

- `Match()` может выполняться конкурентно с `fetchAndUpdate()` — параллельные читатели
  не блокируются на время перестроения автомата.
- `Update()` эксклюзивно блокирует Manager на время замены всех goroutine.

## Health / Monitoring

В `metrics` добавлен gauge `arxsentinel_blocklist_last_refresh_timestamp_seconds`:

- Устанавливается в `fetchAndUpdate()` после успешного перестроения автомата
- Метка `list` — имя списка (из `ListConfig.Name`)
- Можно удалить через `CleanupBlocklistLabels(name)` при удалении списка из конфига

Пример PromQL для мониторинга свежести блоклистов:
```promql
time() - arxsentinel_blocklist_last_refresh_timestamp_seconds{list="bad_ips"} > 3600
```
→ `bad_ips` не обновлялся больше часа.
