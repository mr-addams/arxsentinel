# ArxSentinel — Руководство по развёртыванию в Docker

ArxSentinel поставляется в виде distroless Docker-образа (~12 МБ, amd64 + arm64).
Он работает от непривилегированного пользователя (uid 65532), выставляет метрики Prometheus на `:9117`
и записывает события угроз в примонтированную директорию, которую читает Fail2Ban на хосте.

## Быстрый старт

```bash
# Создать директорию логов угроз (доступна для uid 65532 контейнера)
sudo mkdir -p /var/log/arxsentinel
sudo chown 65532:65532 /var/log/arxsentinel

# Запустить с дефолтными параметрами — следит за /var/log/nginx/access.log
docker run -d \
  --name arxsentinel \
  --restart unless-stopped \
  -v /var/log/nginx/access.log:/var/log/nginx/access.log:ro \
  -v /var/log/arxsentinel:/var/log/arxsentinel \
  -p 127.0.0.1:9117:9117 \
  ghcr.io/mr-addams/arxsentinel:latest
```

## Docker Compose

```bash
cd deploy/container/docker

# Скопировать и отредактировать файл переменных
cp .env.example .env
# Отредактировать .env: установить LOG_FILE и THREAT_LOG_DIR

# Создать директорию логов угроз
sudo mkdir -p /var/log/arxsentinel
sudo chown 65532:65532 /var/log/arxsentinel

# Запустить
docker compose up -d

# Посмотреть логи
docker compose logs -f arxsentinel
```

Compose-файл находится в [`deploy/container/docker/docker-compose.yml`](deploy/container/docker/docker-compose.yml).

## Конфигурация

### Примонтированные тома

| Точка примонтирования в контейнере | Назначение | Режим |
|---|---|---|
| `/var/log/nginx/access.log` | Лог доступа для наблюдения | `ro` |
| `/var/log/arxsentinel` | Лог угроз + операционный лог | `rw` |
| `/etc/arxsentinel/config.yaml` | Пользовательский конфиг (опционально) | `ro` |
| `/tmp` | PID-файл | `rw` (tmpfs) |

### Переменные окружения

Все скалярные поля конфигурации можно переопределить через `ARXSENTINEL_*` переменные окружения.
Они имеют приоритет над примонтированным `config.yaml`.

> **Примечание:** Поля-массивы (пути, дополнительные паттерны, конфиги ботов) нельзя задать через env vars.
> Настройте их в примонтированном `config.yaml` вместо этого.

#### General, логирование и парсер

| Переменная | Тип | Дефолт | Описание |
|---|---|---|---|
| `ARXSENTINEL_GENERAL_LOG_FILE` | string | `/var/log/nginx/access.log` | Путь лога доступа внутри контейнера |
| `ARXSENTINEL_GENERAL_PID_FILE` | string | `/tmp/arxsentinel.pid` | Путь PID-файла |
| `ARXSENTINEL_GENERAL_LINES_BUF_SIZE` | int | `1000` | Размер буфера канала |
| `ARXSENTINEL_GENERAL_TAIL_RETRY_INTERVAL` | duration | `5s` | Интервал retry при недоступном файле |
| `ARXSENTINEL_GENERAL_STATS_INTERVAL` | duration | `300s` | Интервал лога статистики |
| `ARXSENTINEL_LOGGING_DEBUG` | bool | `false` | Включить debug-теги логирования |
| `ARXSENTINEL_LOGGING_CONSOLE_COLOR` | bool | `false` | ANSI-раскраска в консоли |
| `ARXSENTINEL_PARSER_PROFILE` | string | `` | Профиль сервера: `apache`, `caddy`, `traefik`, `haproxy-http` |
| `ARXSENTINEL_PARSER_LOG_FORMAT` | string | `combined` | Формат лога: `combined`, `json`, `regex` |
| `ARXSENTINEL_PARSER_REGEX_PATTERN` | string | `` | Go regex (обязателен при `log_format=regex`) |
| `ARXSENTINEL_PARSER_TIMEZONE` | string | `UTC` | Временная зона (зарезервирована, не подключена) |
| `ARXSENTINEL_PARSER_JSON_REMOTE_ADDR` | string | `remote_addr` | JSON-ключ → IP клиента (log_format=json) |
| `ARXSENTINEL_PARSER_JSON_TIME` | string | `time_iso8601` | JSON-ключ → временная метка |
| `ARXSENTINEL_PARSER_JSON_REQUEST` | string | `request` | JSON-ключ → строка запроса |
| `ARXSENTINEL_PARSER_JSON_STATUS` | string | `status` | JSON-ключ → HTTP-статус |
| `ARXSENTINEL_PARSER_JSON_BYTES_SENT` | string | `bytes_sent` | JSON-ключ → размер ответа |
| `ARXSENTINEL_PARSER_JSON_REFERER` | string | `http_referer` | JSON-ключ → заголовок Referer |
| `ARXSENTINEL_PARSER_JSON_USER_AGENT` | string | `http_user_agent` | JSON-ключ → заголовок User-Agent |
| `ARXSENTINEL_PARSER_JSON_REAL_IP` | string | `real_ip` | JSON-ключ → реальный IP клиента (за прокси) |

#### Скоринг и состояние

| Переменная | Тип | Дефолт | Описание |
|---|---|---|---|
| `ARXSENTINEL_SCORING_ALERT_THRESHOLD` | int | `50` | Порог WARN |
| `ARXSENTINEL_SCORING_BAN_THRESHOLD` | int | `80` | Порог THREAT (блокировка) |
| `ARXSENTINEL_SCORING_OBSERVATION_WINDOW` | duration | `300s` | Окно накопления очков |
| `ARXSENTINEL_SCORING_DECAY` | string | `linear` | Алгоритм затухания |
| `ARXSENTINEL_STATE_GC_INTERVAL` | duration | `60s` | Интервал сборки мусора |
| `ARXSENTINEL_STATE_MAX_TRACKED_IPS` | int | `100000` | Макс. отслеживаемых IP (LRU вытеснение) |

#### Детекторы

| Переменная | Тип | Дефолт | Описание |
|---|---|---|---|
| `ARXSENTINEL_DETECTORS_PROBE_ENABLED` | bool | `true` | Включить сканер проб |
| `ARXSENTINEL_DETECTORS_PROBE_SCORE` | int | `25` | Очки за попадание по пути пробы |
| `ARXSENTINEL_DETECTORS_BRUTEFORCE_ENABLED` | bool | `true` | Включить детектор bruteforce по ratio 404 |
| `ARXSENTINEL_DETECTORS_BRUTEFORCE_MIN_REQUESTS` | int | `10` | Мин. запросов перед проверкой |
| `ARXSENTINEL_DETECTORS_BRUTEFORCE_RATIO_THRESHOLD` | float | `0.6` | Порог ratio 404 |
| `ARXSENTINEL_DETECTORS_BRUTEFORCE_SCORE` | int | `30` | Очки за попадание bruteforce |
| `ARXSENTINEL_DETECTORS_CRAWLER_ENABLED` | bool | `true` | Включить детектор последовательного crawler |
| `ARXSENTINEL_DETECTORS_CRAWLER_MIN_SEQUENTIAL` | int | `5` | Мин. последовательные запросы перед триггером |
| `ARXSENTINEL_DETECTORS_CRAWLER_SCORE` | int | `20` | Очки за попадание crawler |
| `ARXSENTINEL_DETECTORS_NOASSET_ENABLED` | bool | `true` | Включить детектор ботов без ассетов |
| `ARXSENTINEL_DETECTORS_NOASSET_MIN_PAGE_REQUESTS` | int | `3` | Мин. запросов страниц перед проверкой |
| `ARXSENTINEL_DETECTORS_NOASSET_ASSET_RATIO_THRESHOLD` | float | `0.1` | Порог ratio ассетов |
| `ARXSENTINEL_DETECTORS_NOASSET_SCORE` | int | `20` | Очки за попадание no-asset |
| `ARXSENTINEL_DETECTORS_RATE_ENABLED` | bool | `true` | Включить детектор аномалии rate |
| `ARXSENTINEL_DETECTORS_RATE_WINDOW` | duration | `60s` | Окно подсчёта rate |
| `ARXSENTINEL_DETECTORS_RATE_THRESHOLD` | int | `100` | Запросов в окне для триггера |
| `ARXSENTINEL_DETECTORS_RATE_SCORE` | int | `25` | Очки за попадание rate |
| `ARXSENTINEL_DETECTORS_USERAGENT_ENABLED` | bool | `true` | Включить детектор аномалии UA |
| `ARXSENTINEL_DETECTORS_USERAGENT_SCANNER_SCORE` | int | `40` | Очки за scanner UA |
| `ARXSENTINEL_DETECTORS_USERAGENT_GRABBER_SCORE` | int | `20` | Очки за grabber UA |
| `ARXSENTINEL_DETECTORS_USERAGENT_AUTOMATION_SCORE` | int | `15` | Очки за automation tool UA |
| `ARXSENTINEL_DETECTORS_USERAGENT_EMPTY_UA_SCORE` | int | `30` | Очки за пустой UA |
| `ARXSENTINEL_DETECTORS_OVERFLOW_ENABLED` | bool | `true` | Включить детектор overflow/WAF bypass |
| `ARXSENTINEL_DETECTORS_OVERFLOW_MAX_URL_LENGTH` | int | `2048` | Порог длины URL |
| `ARXSENTINEL_DETECTORS_OVERFLOW_SCORE` | int | `30` | Очки за попадание overflow |
| `ARXSENTINEL_DETECTORS_BADBOT_ENABLED` | bool | `true` | Включить community blocklist |
| `ARXSENTINEL_DETECTORS_BADBOT_SCORE` | int | `60` | Очки за совпадение в blocklist |
| `ARXSENTINEL_DETECTORS_BADBOT_CHECK_UA` | bool | `true` | Проверить UA против badbot-ua листа |
| `ARXSENTINEL_DETECTORS_BADBOT_CHECK_REFERRER` | bool | `false` | Проверить Referer против badbot-ref листа |

#### Whitelist, chain guard, output, метрики

| Переменная | Тип | Дефолт | Описание |
|---|---|---|---|
| `ARXSENTINEL_WHITELIST_FAKE_BOT_SCORE` | int | `35` | Штраф за fake bot |
| `ARXSENTINEL_WHITELIST_DNS_VERIFY_TIMEOUT` | duration | `2s` | Timeout верификации DNS ботов |
| `ARXSENTINEL_WHITELIST_DNS_CACHE_POSITIVE_TTL` | duration | `24h` | TTL положительного DNS-кэша |
| `ARXSENTINEL_WHITELIST_DNS_CACHE_NEGATIVE_TTL` | duration | `1h` | TTL отрицательного DNS-кэша |
| `ARXSENTINEL_WHITELIST_DNS_CACHE_IP_LIST_REFRESH` | duration | `24h` | Интервал обновления диапазонов IP ботов |
| `ARXSENTINEL_WHITELIST_CUSTOM_IPS` | CSV | `` | Доверенные IP (разделены запятой) |
| `ARXSENTINEL_WHITELIST_CUSTOM_CIDRS` | CSV | `` | Доверенные подсети (разделены запятой) |
| `ARXSENTINEL_CHAIN_GUARD_ENABLED` | bool | `false` | Включить проверку целостности цепи прокси |
| `ARXSENTINEL_CHAIN_GUARD_WARNINGS_LOG` | string | `` | Путь лога предупреждений (требуется если включено) |
| `ARXSENTINEL_CHAIN_GUARD_CLOUDFLARE_ENABLED` | bool | `true` | Включить проверку диапазонов IP Cloudflare |
| `ARXSENTINEL_CHAIN_GUARD_CLOUDFLARE_REFRESH_INTERVAL` | duration | `24h` | Интервал обновления списка IP Cloudflare |
| `ARXSENTINEL_CHAIN_GUARD_BOGON_ENABLED` | bool | `true` | Включить проверку bogon/RFC1918/CGNAT |
| `ARXSENTINEL_BLOCKLIST_STORAGE` | string | `` | Путь кэша blocklist на диск |
| `ARXSENTINEL_OUTPUT_THREAT_LOG` | string | `/var/log/arxsentinel/threats.log` | Путь лога угроз |
| `ARXSENTINEL_OUTPUT_OPERATIONAL_LOG` | string | `/var/log/arxsentinel/sentinel.log` | Путь операционного лога |
| `ARXSENTINEL_METRICS_ENABLED` | bool | `false` | Включить endpoint Prometheus |
| `ARXSENTINEL_METRICS_LISTEN_ADDR` | string | `:9117` | Адрес прослушивания метрик |
| `ARXSENTINEL_METRICS_USERNAME` | string | `` | Пользователь Basic auth |
| `ARXSENTINEL_METRICS_PASSWORD_HASH` | string | `` | bcrypt хэш пароля |
| `ARXSENTINEL_PIPELINE_BUFFER_SIZE` | int | `8192` | Глубина буфера канала (увеличить при всплесках) |
| `ARXSENTINEL_PIPELINE_SHUTDOWN_TIMEOUT` | duration | `15s` | Окно graceful shutdown |

Полный список: все переменные `ARXSENTINEL_<SECTION>_<FIELD>` определены в
`internal/sys/config/config.go` (функция `applyEnvOverrides`).

### Пользовательский конфиг-файл

Примонтируйте собственный `config.yaml` для переопределения дефолтов образа:

```bash
docker run -d \
  -v ./my-config.yaml:/etc/arxsentinel/config.yaml:ro \
  -v /var/log/nginx/access.log:/var/log/nginx/access.log:ro \
  -v /var/log/arxsentinel:/var/log/arxsentinel \
  ghcr.io/mr-addams/arxsentinel:latest
```

## Интеграция Prometheus

Endpoint метрик включен по умолчанию в Docker-образе.

```bash
# Проверить endpoint
curl http://localhost:9117/metrics | grep arx

# Добавить в Prometheus — вставьте job из deploy/container/docker/prometheus-scrape.yml
# в секцию scrape_configs вашего prometheus.yml
```

Графаны-дашборды: смотрите [`deploy/grafana/`](deploy/grafana/) для готовых JSON-дашбордов.

### Basic auth для метрик

```bash
# Сгенерировать bcrypt-хэш (cost 10):
htpasswd -bnBC 10 "" your-password | tr -d ':\n'

# Установить через env vars:
docker run -d \
  -e ARXSENTINEL_METRICS_USERNAME=prometheus \
  -e 'ARXSENTINEL_METRICS_PASSWORD_HASH=$2y$10$...' \
  ...
```

## Интеграция Fail2Ban

ArxSentinel записывает события угроз в директорию хоста, примонтированную в `/var/log/arxsentinel`.
Настройте Fail2Ban на хосте для чтения `threats.log` из этой директории:

```ini
# /etc/fail2ban/jail.d/arxsentinel.conf
[arxsentinel]
enabled  = true
filter   = arxsentinel
logpath  = /var/log/arxsentinel/threats.log
maxretry = 1
bantime  = 3600
```

Конфиги filter и jail для Fail2Ban находятся в [`deploy/fail2ban/`](deploy/fail2ban/).

## Мониторинг нескольких потоков

Для наблюдения за несколькими лог-файлами независимо примонтируйте пользовательский `config.yaml`
с использованием секции `streams:` вместо `general.log_file`:

```yaml
# config.yaml
streams:
  - name: site1
    inputs:
      - type: file
        path: /logs/site1.access.log
        parser: combined
    outputs:
      - type: file
        path: /threats/site1.threats.log
        format: fail2ban
  - name: site2
    inputs:
      - type: file
        path: /logs/site2.access.log
        parser: combined
    outputs:
      - type: file
        path: /threats/site2.threats.log
        format: fail2ban
```

```bash
docker run -d \
  -v ./config.yaml:/etc/arxsentinel/config.yaml:ro \
  -v /var/log/nginx:/logs:ro \
  -v /var/log/arxsentinel:/threats \
  ghcr.io/mr-addams/arxsentinel:latest
```

> **YAML-exclusive features** — следующие функции нельзя настроить через env vars и требуют
> пользовательского `config.yaml`:
> `streams:`, `inputs:`, `outputs:`, `executors:`, `pipelines:`, массивы `paths:` для отдельных детекторов.
> Полные готовые примеры: `/etc/arxsentinel/config.yaml.example` (внутри контейнера)
> или [`config.example.yaml`](../../../../config.example.yaml) в репозитории.

## Локальная сборка

```bash
# Собрать образ (требует Docker Buildx)
docker build -f deploy/container/docker/Dockerfile --build-arg VERSION=$(cat VERSION) -t arxsentinel:local .

# Запустить интеграционные тесты контейнера (требует собранный выше образ)
go test -v -tags container ./tests/container/ -timeout 120s
```

## Детали образа

| Параметр | Значение |
|---|---|
| Base image | `gcr.io/distroless/static-debian12:nonroot` |
| Пользователь | `nonroot` (uid 65532) |
| Выставленный порт | `9117` (метрики Prometheus) |
| Размер | ~12 МБ |
| Архитектуры | `linux/amd64`, `linux/arm64` |
| Registry | `ghcr.io/mr-addams/arxsentinel` |
