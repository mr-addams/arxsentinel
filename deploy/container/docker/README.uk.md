# ArxSentinel — Посібник розгортання в Docker

ArxSentinel поставляється як distroless Docker-образ (~12 МБ, amd64 + arm64).
Працює від непривілейованого користувача (uid 65532), виставляє метрики Prometheus на `:9117`
та записує події загроз у змонтовану директорію, яку читає Fail2Ban на хості.

## Швидкий старт

```bash
# Створити директорію логів загроз (доступна для uid 65532 контейнера)
sudo mkdir -p /var/log/arxsentinel
sudo chown 65532:65532 /var/log/arxsentinel

# Запустити з дефолтними налаштуваннями — спостерігає /var/log/nginx/access.log
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

# Скопіювати та відредагувати файл змінних оточення
cp .env.example .env
# Відредагувати .env: встановити LOG_FILE та THREAT_LOG_DIR

# Створити директорію логів загроз
sudo mkdir -p /var/log/arxsentinel
sudo chown 65532:65532 /var/log/arxsentinel

# Запустити
docker compose up -d

# Переглянути логи
docker compose logs -f arxsentinel
```

Файл Compose знаходиться в [`deploy/container/docker/docker-compose.yml`](deploy/container/docker/docker-compose.yml).

## Права доступу до логів nginx

Якщо nginx працює на **хості** (не в контейнері), його логи належать групі `nginx` з правами
`640` (`-rw-r-----`). Контейнер ArxSentinel працює від `uid 65532`, який не входить до групи
`nginx` — спроба читати лог повертає `permission denied`.

**Симптом:**
```
[TAIL] file unavailable (open /var/log/nginx/access.log: permission denied)
```

**Рішення — додати GID групи nginx як supplementary group контейнера:**

```bash
# 1. Дізнатись GID групи nginx на хості
getent group nginx   # → nginx:x:993:...
```

У `docker-compose.yml`:
```yaml
services:
  arxsentinel:
    group_add:
      - "993"   # GID групи nginx; замінити на реальне значення
```

У `docker run`:
```bash
docker run ... --group-add 993 ghcr.io/mr-addams/arxsentinel:latest
```

> `group_add` додає supplementary group до процесу контейнера, не змінюючи основний `uid/gid`.
> Права на запис у `/var/log/arxsentinel` зберігаються — директорія належить `uid 65532`.

---

## Конфігурація

### Змонтовані томи

| Точка монтування в контейнері | Назначення | Режим |
|---|---|---|
| `/var/log/nginx/access.log` | Лог доступу для спостереження | `ro` |
| `/var/log/arxsentinel` | Лог загроз + операційний лог | `rw` |
| `/etc/arxsentinel/config.yaml` | Користувацька конфігурація (опціонально) | `ro` |
| `/tmp` | PID-файл | `rw` (tmpfs) |

### Змінні оточення

Усі скалярні поля конфігурації можна перевизначити через `ARXSENTINEL_*` змінні оточення.
Вони мають пріоритет над змонтованим `config.yaml`.

> **Примітка:** Поля-масиви (шляхи, додаткові шаблони, конфігурації ботів) неможливо встановити через env vars.
> Налаштуйте їх у змонтованому `config.yaml` натомість.

#### General, логування та парсер

| Змінна | Тип | Дефолт | Опис |
|---|---|---|---|
| `ARXSENTINEL_GENERAL_LOG_FILE` | string | `/var/log/nginx/access.log` | Шлях лога доступу всередину контейнера |
| `ARXSENTINEL_GENERAL_PID_FILE` | string | `/tmp/arxsentinel.pid` | Шлях PID-файла |
| `ARXSENTINEL_GENERAL_LINES_BUF_SIZE` | int | `1000` | Розмір буфера каналу |
| `ARXSENTINEL_GENERAL_TAIL_RETRY_INTERVAL` | duration | `5s` | Інтервал retry при недоступному файлі |
| `ARXSENTINEL_GENERAL_STATS_INTERVAL` | duration | `300s` | Інтервал логу статистики |
| `ARXSENTINEL_LOGGING_DEBUG` | bool | `false` | Увімкнути debug-теги логування |
| `ARXSENTINEL_LOGGING_CONSOLE_COLOR` | bool | `false` | ANSI-розфарбування в консолі |
| `ARXSENTINEL_PARSER_PROFILE` | string | `` | Профіль сервера: `apache`, `caddy`, `traefik`, `haproxy-http` |
| `ARXSENTINEL_PARSER_LOG_FORMAT` | string | `combined` | Формат логу: `combined`, `json`, `regex` |
| `ARXSENTINEL_PARSER_REGEX_PATTERN` | string | `` | Go regex (обов'язковий при `log_format=regex`) |
| `ARXSENTINEL_PARSER_TIMEZONE` | string | `UTC` | Часовий пояс (зарезервовано, не підключено) |
| `ARXSENTINEL_PARSER_JSON_REMOTE_ADDR` | string | `remote_addr` | JSON-ключ → IP клієнта (log_format=json) |
| `ARXSENTINEL_PARSER_JSON_TIME` | string | `time_iso8601` | JSON-ключ → часова мітка |
| `ARXSENTINEL_PARSER_JSON_REQUEST` | string | `request` | JSON-ключ → рядок запиту |
| `ARXSENTINEL_PARSER_JSON_STATUS` | string | `status` | JSON-ключ → HTTP-статус |
| `ARXSENTINEL_PARSER_JSON_BYTES_SENT` | string | `bytes_sent` | JSON-ключ → розмір відповіді |
| `ARXSENTINEL_PARSER_JSON_REFERER` | string | `http_referer` | JSON-ключ → заголовок Referer |
| `ARXSENTINEL_PARSER_JSON_USER_AGENT` | string | `http_user_agent` | JSON-ключ → заголовок User-Agent |
| `ARXSENTINEL_PARSER_JSON_REAL_IP` | string | `real_ip` | JSON-ключ → справжня IP клієнта (за проксі) |

#### Скоринг та стан

| Змінна | Тип | Дефолт | Опис |
|---|---|---|---|
| `ARXSENTINEL_SCORING_ALERT_THRESHOLD` | int | `50` | Поріг WARN |
| `ARXSENTINEL_SCORING_BAN_THRESHOLD` | int | `80` | Поріг THREAT (блокування) |
| `ARXSENTINEL_SCORING_OBSERVATION_WINDOW` | duration | `300s` | Вікно накопичення балів |
| `ARXSENTINEL_SCORING_DECAY` | string | `linear` | Алгоритм затухання |
| `ARXSENTINEL_STATE_GC_INTERVAL` | duration | `60s` | Інтервал збирання сміття |
| `ARXSENTINEL_STATE_MAX_TRACKED_IPS` | int | `100000` | Макс. відстежуваних IP (LRU витіснення) |

#### Джерело (syslog)

| Змінна | Тип | Дефолт | Опис |
|---|---|---|---|
| `ARXSENTINEL_SYSLOG_MAX_CONNECTIONS` | int | `1000` | Макс. одночасних TCP-з'єднань syslog (H5) |

#### Детектори

| Змінна | Тип | Дефолт | Опис |
|---|---|---|---|
| `ARXSENTINEL_DETECTORS_PROBE_ENABLED` | bool | `true` | Увімкнути сканер зондів |
| `ARXSENTINEL_DETECTORS_PROBE_SCORE` | int | `25` | Бали за влучення по шляху зонду |
| `ARXSENTINEL_DETECTORS_BRUTEFORCE_ENABLED` | bool | `true` | Увімкнути детектор bruteforce за ratio 404 |
| `ARXSENTINEL_DETECTORS_BRUTEFORCE_MIN_REQUESTS` | int | `10` | Мін. запитів перед перевіркою |
| `ARXSENTINEL_DETECTORS_BRUTEFORCE_RATIO_THRESHOLD` | float | `0.6` | Поріг ratio 404 |
| `ARXSENTINEL_DETECTORS_BRUTEFORCE_SCORE` | int | `30` | Бали за влучення bruteforce |
| `ARXSENTINEL_DETECTORS_CRAWLER_ENABLED` | bool | `true` | Увімкнути детектор послідовного crawler |
| `ARXSENTINEL_DETECTORS_CRAWLER_MIN_SEQUENTIAL` | int | `5` | Мін. послідовні запити перед тригером |
| `ARXSENTINEL_DETECTORS_CRAWLER_SCORE` | int | `20` | Бали за влучення crawler |
| `ARXSENTINEL_DETECTORS_NOASSET_ENABLED` | bool | `true` | Увімкнути детектор ботів без активів |
| `ARXSENTINEL_DETECTORS_NOASSET_MIN_PAGE_REQUESTS` | int | `3` | Мін. запитів сторінок перед перевіркою |
| `ARXSENTINEL_DETECTORS_NOASSET_ASSET_RATIO_THRESHOLD` | float | `0.1` | Поріг ratio активів |
| `ARXSENTINEL_DETECTORS_NOASSET_SCORE` | int | `20` | Бали за влучення no-asset |
| `ARXSENTINEL_DETECTORS_RATE_ENABLED` | bool | `true` | Увімкнути детектор аномалії rate |
| `ARXSENTINEL_DETECTORS_RATE_WINDOW` | duration | `60s` | Вікно підрахунку rate |
| `ARXSENTINEL_DETECTORS_RATE_THRESHOLD` | int | `100` | Запитів у вікні для тригеру |
| `ARXSENTINEL_DETECTORS_RATE_SCORE` | int | `25` | Бали за влучення rate |
| `ARXSENTINEL_DETECTORS_USERAGENT_ENABLED` | bool | `true` | Увімкнути детектор аномалії UA |
| `ARXSENTINEL_DETECTORS_USERAGENT_SCANNER_SCORE` | int | `40` | Бали за scanner UA |
| `ARXSENTINEL_DETECTORS_USERAGENT_GRABBER_SCORE` | int | `20` | Бали за grabber UA |
| `ARXSENTINEL_DETECTORS_USERAGENT_AUTOMATION_SCORE` | int | `15` | Бали за automation tool UA |
| `ARXSENTINEL_DETECTORS_USERAGENT_EMPTY_UA_SCORE` | int | `30` | Бали за порожній UA |
| `ARXSENTINEL_DETECTORS_OVERFLOW_ENABLED` | bool | `true` | Увімкнути детектор overflow/WAF bypass |
| `ARXSENTINEL_DETECTORS_OVERFLOW_MAX_URL_LENGTH` | int | `2048` | Поріг довжини URL |
| `ARXSENTINEL_DETECTORS_OVERFLOW_SCORE` | int | `30` | Бали за влучення overflow |
| `ARXSENTINEL_DETECTORS_BADBOT_ENABLED` | bool | `true` | Увімкнути community blocklist |
| `ARXSENTINEL_DETECTORS_BADBOT_SCORE` | int | `60` | Бали за збіг у blocklist |
| `ARXSENTINEL_DETECTORS_BADBOT_CHECK_UA` | bool | `true` | Перевірити UA проти badbot-ua списку |
| `ARXSENTINEL_DETECTORS_BADBOT_CHECK_REFERRER` | bool | `false` | Перевірити Referer проти badbot-ref списку |

#### Whitelist, chain guard, output, метрики

| Змінна | Тип | Дефолт | Опис |
|---|---|---|---|
| `ARXSENTINEL_WHITELIST_FAKE_BOT_SCORE` | int | `35` | Штраф за fake bot |
| `ARXSENTINEL_WHITELIST_DNS_VERIFY_TIMEOUT` | duration | `2s` | Timeout верифікації DNS ботів |
| `ARXSENTINEL_WHITELIST_DNS_CACHE_POSITIVE_TTL` | duration | `24h` | TTL позитивного DNS-кешу |
| `ARXSENTINEL_WHITELIST_DNS_CACHE_NEGATIVE_TTL` | duration | `1h` | TTL негативного DNS-кешу |
| `ARXSENTINEL_WHITELIST_DNS_CACHE_IP_LIST_REFRESH` | duration | `24h` | Інтервал оновлення діапазонів IP ботів |
| `ARXSENTINEL_WHITELIST_CUSTOM_IPS` | CSV | `` | Довірені IP (розділені комою) |
| `ARXSENTINEL_WHITELIST_CUSTOM_CIDRS` | CSV | `` | Довірені підмережі (розділені комою) |
| `ARXSENTINEL_CHAIN_GUARD_ENABLED` | bool | `false` | Увімкнути перевірку цілісності ланцюга проксі |
| `ARXSENTINEL_CHAIN_GUARD_WARNINGS_LOG` | string | `` | Шлях лога попереджень (потрібний якщо увімкнено) |
| `ARXSENTINEL_CHAIN_GUARD_CLOUDFLARE_ENABLED` | bool | `true` | Увімкнути перевірку діапазонів IP Cloudflare |
| `ARXSENTINEL_CHAIN_GUARD_CLOUDFLARE_REFRESH_INTERVAL` | duration | `24h` | Інтервал оновлення списку IP Cloudflare |
| `ARXSENTINEL_CHAIN_GUARD_BOGON_ENABLED` | bool | `true` | Увімкнути перевірку bogon/RFC1918/CGNAT |
| `ARXSENTINEL_BLOCKLIST_STORAGE` | string | `` | Шлях кешу blocklist на диск |
| `ARXSENTINEL_OUTPUT_THREAT_LOG` | string | `/var/log/arxsentinel/threats.log` | Шлях лога загроз |
| `ARXSENTINEL_OUTPUT_OPERATIONAL_LOG` | string | `/var/log/arxsentinel/sentinel.log` | Шлях операційного логу |
| `ARXSENTINEL_METRICS_ENABLED` | bool | `false` | Увімкнути endpoint Prometheus |
| `ARXSENTINEL_METRICS_LISTEN_ADDR` | string | `:9117` | Адреса прослуховування метрик |
| `ARXSENTINEL_METRICS_USERNAME` | string | `` | Користувач Basic auth |
| `ARXSENTINEL_METRICS_PASSWORD_HASH` | string | `` | bcrypt хеш пароля |
| `ARXSENTINEL_PIPELINE_BUFFER_SIZE` | int | `8192` | Глибина буфера каналу (збільшити при сплесках) |
| `ARXSENTINEL_PIPELINE_SHUTDOWN_TIMEOUT` | duration | `15s` | Вікно graceful shutdown |

Повний список: усі змінні `ARXSENTINEL_<SECTION>_<FIELD>` визначені в
`internal/sys/config/config.go` (функція `applyEnvOverrides`).

### Користувацький файл конфігурації

Змонтуйте власний `config.yaml` для перевизначення дефолтів образу:

```bash
docker run -d \
  -v ./my-config.yaml:/etc/arxsentinel/config.yaml:ro \
  -v /var/log/nginx/access.log:/var/log/nginx/access.log:ro \
  -v /var/log/arxsentinel:/var/log/arxsentinel \
  ghcr.io/mr-addams/arxsentinel:latest
```

## Інтеграція Prometheus

Endpoint метрик увімкнено за замовчуванням в Docker-образі.

```bash
# Перевірити endpoint
curl http://localhost:9117/metrics | grep arx

# Додати до Prometheus — вставте job з deploy/container/docker/prometheus-scrape.yml
# у секцію scrape_configs вашого prometheus.yml
```

Grafana dashboard: див. [`deploy/grafana/`](deploy/grafana/) для готових JSON-дашбордів.

### Basic auth для метрик

```bash
# Генерувати bcrypt-хеш (cost 10):
htpasswd -bnBC 10 "" your-password | tr -d ':\n'

# Встановити через env vars:
docker run -d \
  -e ARXSENTINEL_METRICS_USERNAME=prometheus \
  -e 'ARXSENTINEL_METRICS_PASSWORD_HASH=$2y$10$...' \
  ...
```

## Інтеграція Fail2Ban

ArxSentinel записує події загроз до директорії хоста, змонтованої в `/var/log/arxsentinel`.
Налаштуйте Fail2Ban на хості для читання `threats.log` з цієї директорії:

```ini
# /etc/fail2ban/jail.d/arxsentinel.conf
[arxsentinel]
enabled  = true
filter   = arxsentinel
logpath  = /var/log/arxsentinel/threats.log
maxretry = 1
bantime  = 3600
```

Конфіги filter та jail для Fail2Ban знаходяться в [`deploy/fail2ban/`](deploy/fail2ban/).

## Спостереження за кількома потоками

Щоб спостерігати за кількома лог-файлами незалежно, змонтуйте користувацький `config.yaml`
з використанням секції `streams:` замість `general.log_file`:

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

> **YAML-only функції** — наступні функції неможливо налаштувати через env vars і потребують
> користувацького `config.yaml`:
> `streams:`, `inputs:`, `outputs:`, `executors:`, `pipelines:`, масиви `paths:` для окремих детекторів.
> Повні готові приклади: `/etc/arxsentinel/config.yaml.example` (всередину контейнера)
> або [`config.reference.yaml`](../../../../cookbook/config.reference.yaml) у репозиторії.

## Локальна збірка

```bash
# Збудувати образ (потребує Docker Buildx)
docker build -f deploy/container/docker/Dockerfile --build-arg VERSION=$(cat VERSION) -t arxsentinel:local .

# Запустити інтеграційні тести контейнера (потребує зібраний вище образ)
go test -v -tags container ./tests/container/ -timeout 120s
```

## Деталі образу

| Параметр | Значення |
|---|---|
| Base image | `gcr.io/distroless/static-debian12:nonroot` |
| Користувач | `nonroot` (uid 65532) |
| Виставлений порт | `9117` (метрики Prometheus) |
| Розмір | ~12 МБ |
| Архітектури | `linux/amd64`, `linux/arm64` |
| Registry | `ghcr.io/mr-addams/arxsentinel` |
