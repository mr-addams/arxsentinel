# pkg/detector — Plugin registry для детекторов

Центральный регистр, общие типы и вспомогательные функции для детекторных
плагинов ArxSentinel. Каждый детектор саморегистрируется через `init()`,
а pipeline получает рабочий экземпляр через `Build(ctx, name, cfg, shared)`.
Детекторы **stateless** — всё per-IP состояние передаётся через
`plugin.IPView` на каждый вызов `Detect`.

Пакет зависит только от `pkg/plugin`, `pkg/execplugin` и
`pkg/pluginregistry`. Он **не импортирует ничего из `internal/`**,
поэтому может использоваться как самостоятельная библиотека.

## Структура пакета

```
pkg/detector/
├── registry.go       # Registry (Register/Build/Names), shared types
│                     # (DetectorConfig / Matcher / SharedResources) и Factory
├── params.go         # Exported helpers для парсинга конфига детектора:
│                     # GetInt / GetFloat64 / GetBool / GetDuration / GetStrings
└── registry_test.go  # Registry-infra тесты: Names, Disabled, Unknown
```

## Sub-пакеты (детекторы)

Каждый детектор живёт в отдельном sub-пакете для того, чтобы профильные
сборки могли исключать неиспользуемые детекторы из бинаря (tree-shaking).

| Путь sub-пакета | Register-имя | Файлы |
|-----------------|--------------|-------|
| `pkg/detector/probe/`      | `probe`      | `probe.go`, `manifest.go`, `probe_test.go` |
| `pkg/detector/rate/`       | `rate`       | `rate.go`, `manifest.go`, `rate_test.go` |
| `pkg/detector/bruteforce/` | `bruteforce` | `bruteforce.go`, `manifest.go`, `bruteforce_test.go` |
| `pkg/detector/crawler/`    | `crawler`    | `crawler.go`, `manifest.go`, `crawler_test.go` |
| `pkg/detector/noasset/`    | `noasset`    | `noasset.go`, `manifest.go`, `noasset_test.go` |
| `pkg/detector/badbot/`     | `badbot`     | `badbot.go`, `manifest.go`, `badbot_test.go` |
| `pkg/detector/overflow/`   | `overflow`   | `overflow.go`, `manifest.go`, `overflow_test.go` |
| `pkg/detector/useragent/`  | `ua`         | `useragent.go`, `manifest.go`, `useragent_test.go` |

Каждый sub-пакет устроен одинаково:

- `<name>.go` — тип детектора, фабрика и `init()` с `detector.Register("<name>", …)`.
- `manifest.go` — метод `Manifest()` на типе детектора, возвращающий
  `plugin.Manifest`.
- `<name>_test.go` — unit-тесты самого детектора плюс registry smoke-тесты.

**Исключение имени.** Путь `pkg/detector/useragent/` регистрируется под
именем `ua`. В YAML конфигурации и в pipeline-именах используется
`useragent`, но в `detector.Register` и при blank-import — `ua`.

## Подключение (blank-import pattern)

Детекторы подключаются side-effect `init()` через blank-import в файлах
`cmd/arxsentinel/plugins_<profile>.go`:

```go
//go:build minimal
package main

import _ "github.com/mr-addams/arxsentinel/pkg/detector/probe"
import _ "github.com/mr-addams/arxsentinel/pkg/detector/rate"
```

Профили `full`, `minimal`, `iot` — **tree-shakeable**: если профиль не
blank-import'ит sub-пакет детектора, Go linker не включает код этого
детектора в бинарь.

R6 (tree-shaking verification) доказано через `go tool nm`:

- `minimal` не содержит символов `pkg/detector/{crawler,noasset,badbot}`.
- `iot` не содержит символов
  `pkg/detector/{rate,bruteforce,crawler,noasset,badbot,useragent}`.

Имя профиля в YAML (`name:`) совпадает с Register-именем 1:1, кроме
исключения `useragent`: YAML `name: useragent` ↔ sub-пакет
`pkg/detector/useragent`, Register-имя `ua`.

## Core Types (`registry.go`)

```go
type DetectorConfig struct {
    Enabled bool
    Params  map[string]interface{}  // yaml:",inline"
    Exec    string                  // путь к внешнему exec-плагину
}

type Matcher interface {
    Match(list string, text string) bool
    MatchResult(list string, text string) (string, bool)
}

type SharedResources interface {
    Blocklist() Matcher
}

type Factory func(cfg DetectorConfig, shared SharedResources) (plugin.Detector, error)
```

- `Enabled == false` → `Build` возвращает `(nil, nil)`.
- `Params` — всё, что не `enabled` и не `exec`. Детекторы извлекают
  типизированные значения через helpers из `params.go`.
- `Matcher` — duck-typed: конкретный `*blocklist.Manager` в
  `internal/core/blocklist` удовлетворяет ему неявно, без явного импорта.
- `SharedResources` нужен прежде всего `badbot`.

### Registry API

```go
func Register(name string, f Factory)
func Build(ctx context.Context, name string, cfg DetectorConfig, shared SharedResources) (plugin.Detector, error)
func Names() []string
```

- `Register` паникует при дублирующем имени — это программная ошибка,
  которая должна всплыть на старте.
- `Build` возвращает `(nil, nil)` для disabled-детекторов, живой детектор
  для зарегистрированного имени, exec-обёртку для неизвестного имени с
  `cfg.Exec != ""`, или ошибку иначе.
- `Names` возвращает отсортированный список зарегистрированных имён.

### Exec fallback

Если имя не зарегистрировано, но `cfg.Exec` задан, `Build` делегирует в
`pkg/execplugin` и возвращает обёртку, которая вызывает внешний бинарь
на каждый `Detect`. Это позволяет поставлять произвольный детектор без
перекомпиляции агента.

### Thread safety

Фабричная карта защищена `sync.RWMutex`. `Names()` и `Build()` берут read-
lock, `Register()` — write-lock. `Register` предназначен для запуска из
`init()`; mutex пригодится для любых будущих путей динамической
регистрации и держит race-detector тихим.

## Helpers (`params.go`)

Все helpers работают с `DetectorConfig.Params` и возвращают
`defaultVal`, если ключ отсутствует или тип некорректен. Это
намеренное silent-degradation: ошибка в конфиге одного детектора не
должна падать весь агент.

### `GetInt`

```go
func GetInt(cfg DetectorConfig, key string, defaultVal int) int
```

Принимает `int`, `int64`, `float64` (yaml иногда даёт float64 для целых
чисел). Возвращает `defaultVal` при отсутствии ключа или неподходящем типе.

### `GetFloat64`

```go
func GetFloat64(cfg DetectorConfig, key string, defaultVal float64) float64
```

Принимает `float64`, `int`, `int64`. Возвращает `defaultVal` при отсутствии
ключа или неподходящем типе.

### `GetBool`

```go
func GetBool(cfg DetectorConfig, key string, defaultVal bool) bool
```

Принимает только `bool`. Возвращает `defaultVal` при отсутствии ключа или
некорректном типе.

### `GetDuration`

```go
func GetDuration(cfg DetectorConfig, key string, defaultVal time.Duration) time.Duration
```

Принимает:

- `string` — парсится через `time.ParseDuration` (например, `"30s"`,
  `"1m"`, `"500ms"`).
- `int`, `int64`, `float64` — значение в наносекундах.

Возвращает `defaultVal` при отсутствии ключа, неизвестном типе или
ошибке парсинга.

### `GetStrings`

```go
func GetStrings(cfg DetectorConfig, key string, defaultVal []string) []string
```

Принимает:

- `[]string` — возвращается как есть.
- `[]interface{}` — каждый элемент приводится к `string`; не-строковые
  элементы пропускаются.

Возвращает `defaultVal` при отсутствии ключа или неподходящем типе.

## Историческое

До Flow 076 (2026-06-22) все восемь детекторов жили в одном пакете
`pkg/detector` в файлах `probe.go`, `rate.go`, `bruteforce.go`,
`crawler.go`, `noasset.go`, `badbot.go`, `useragent.go`, `overflow.go`.
После Flow 076 / Task 7.1 детекторы разнесены в sub-пакеты, чтобы:

- включать только нужные детекторы через blank-import профильных файлов;
- позволить Go compiler/linker вырезать неиспользуемые детекторы из
  профильных бинарей (доказано R6 verifier).
