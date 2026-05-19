# ArxSentinel

[![Release](https://img.shields.io/github/v/release/mr-addams/arxsentinel?include_prereleases&label=release)](https://github.com/mr-addams/arxsentinel/releases)
[![Build](https://github.com/mr-addams/arxsentinel/actions/workflows/release.yml/badge.svg)](https://github.com/mr-addams/arxsentinel/actions/workflows/release.yml)
[![License](https://img.shields.io/badge/license-GPL--3.0-blue)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go)](go.mod)
[![Platforms](https://img.shields.io/badge/linux-amd64%20%7C%20arm64-lightgrey?logo=linux)](https://github.com/mr-addams/arxsentinel/releases)
[![Packages](https://img.shields.io/badge/packages-deb%20%7C%20rpm%20%7C%20pacman-blue)](https://github.com/mr-addams/arxsentinel/releases)

Бдительный страж вашего веб-сервера: читает HTTP access-логи в реальном времени, оценивает каждый IP через 7 поведенческих детекторов и блокирует атакующих через Fail2Ban. Работает с nginx, Apache, Caddy, Traefik, HAProxy, LiteSpeed и OpenLiteSpeed.

Поддерживает **nginx, Apache, Caddy, Traefik, HAProxy, LiteSpeed и OpenLiteSpeed** через встроенные профили. nginx работает из коробки без настройки профиля. Caddy и HAProxy требуют минимальной однократной настройки. Произвольные форматы логов — через regex. Несколько лог-файлов в одном процессе.

```
access.log → TailReader → whitelist → tracker → scorer → threats.log → Fail2Ban → iptables
```

## Поддерживаемые HTTP-серверы

### Таблица совместимости

| Сервер | Профиль | Требуемая настройка |
|--------|---------|---------------------|
| nginx | *(по умолчанию — профиль не нужен)* | Нет — nginx combined log format работает из коробки |
| Apache | `apache` | Нет — стандартный CLF |
| Traefik | `traefik` | Нет — стандартный access log (CLF) |
| Caddy | `caddy` | [xcaddy](https://github.com/caddyserver/xcaddy) + плагин [transform-encoder](https://github.com/caddyserver/transform-encoder) |
| HAProxy | `haproxy-http` | `option httplog` в haproxy.cfg + rsyslog для записи в файл |
| LiteSpeed / OpenLiteSpeed | `litespeed` | Нет — стандартный CLF |

> В каждом релизе публикуется таблица **Tested product versions** с точными версиями серверов, на которых валидировалась сборка — см. [GitHub Releases](https://github.com/mr-addams/arxsentinel/releases).

> **nginx:** настройка `profile:` не нужна. Стандартный CombinedParser обрабатывает nginx combined log format из коробки. Укажите только `general.log_file` с путём к вашему access.log.

Встроенные профили — настройка regex и маппинга полей не требуется. Укажите `parser.profile` с именем сервера для Apache, Traefik, Caddy, HAProxy, LiteSpeed или OpenLiteSpeed:

**Пример — Apache:**

```yaml
parser:
  profile: "apache"

general:
  log_file: /var/log/apache2/access.log

output:
  threat_log: /var/log/arxsentinel/threats.log
```

Готовые конфиги для каждого сервера находятся в [`deploy/examples/`](deploy/examples/):

```
deploy/examples/
├── apache/      httpd.conf + sentinel-config.yaml
├── caddy/       Caddyfile + sentinel-config.yaml
├── traefik/     traefik.yml + sentinel-config.yaml
├── haproxy/     haproxy.cfg + sentinel-config.yaml
└── litespeed/   httpd_config.conf + sentinel-config.yaml
```

> **Замечание — HAProxy:** HAProxy включает миллисекунды в временную метку
> (`14:30:00.123`), что не соответствует ожидаемому формату. Sentinel использует
> `time.Time{}` для этого поля. Обнаружение rate-окон работает по системному
> времени, поэтому все детекторы функционируют корректно.

> **Замечание — Caddy:** Встроенный JSON-энкодер Caddy v2 выводит вложенные объекты.
> Профиль `caddy` требует плагина
> [caddy-transform-encoder](https://github.com/caddyserver/transform-encoder)
> для вывода в формате CLF. Смотрите `deploy/examples/caddy/Caddyfile` для настройки.

> **Замечание — LiteSpeed / OpenLiteSpeed:** Оба сервера (LSWS и OLS) по умолчанию пишут Apache CLF —
> настройка формата лога не требуется. Если sentinel стоит за прокси, включите «Use Client IP in Header»
> в WebAdmin («Server Configuration → Use Client IP in Header»), чтобы реальный IP клиента писался
> в `%h` напрямую. Смотрите `deploy/examples/litespeed/` для полного конфига.

## Возможности

- **7 детекторов:** probe-сканирование, rate-аномалия, подозрительный User-Agent, bruteforce (404 ratio), sequential crawler, no-asset bot, URL overflow / WAF bypass
- **DNS-верификация ботов:** Googlebot, Bingbot, Yandex, DuckDuckGo и другие верифицируются по rDNS/fDNS — легитимные краулеры в бан не попадают
- **Multi-stream:** несколько лог-файлов в одном процессе — полная изоляция конвейера на поток
- **Whitelist:** IP, CIDR, UA-подстроки — конфигурируемые списки исключений
- **Линейный decay score:** очки затухают за `observation_window`, нет ложных банов от старого трафика
- **Prometheus-метрики:** `/metrics` на настраиваемом порту (по умолчанию `:9117`), опциональная basic auth с bcrypt; дашборд Grafana в комплекте
- **Health endpoint:** `/health` всегда возвращает `200 {"status":"ok"}` без авторизации — готов для Docker `HEALTHCHECK`, k8s probes и балансировщиков
- **JSON-формат логов:** переключение на JSON-парсинг через `parser.log_format: "json"` без перекомпиляции
- **SIGHUP reload:** конфиг, scorer, парсер и whitelist пересоздаются без перезапуска демона
- **Graceful shutdown:** дренирование буфера строк при SIGTERM
- **Systemd + logrotate + Fail2Ban:** готовые deploy-конфиги в комплекте

## Требования

- Linux x86_64 или arm64 с systemd
- Fail2Ban
- HTTP-сервер, пишущий access.log в поддерживаемом формате (nginx, Apache, Caddy, Traefik, HAProxy, LiteSpeed, OpenLiteSpeed — или произвольный regex)

## Установка

### Быстрая установка — любой дистрибутив (рекомендуется)

Скрипт автоматически определяет дистрибутив и архитектуру, скачивает нужный пакет из GitHub Releases,
устанавливает его через штатный менеджер пакетов, добавляет в автозагрузку и запускает сервис:

```bash
curl -fsSL https://raw.githubusercontent.com/mr-addams/arxsentinel/main/scripts/get.sh | sudo bash
```

Работает на Debian, Ubuntu, Fedora, RHEL, AlmaLinux, Rocky Linux и Arch Linux.
Требует `curl` и `sudo`. Fail2Ban устанавливается автоматически, если отсутствует.

Сервис запускается сразу и работает с nginx из коробки — профиль не нужен. Чтобы переключиться на другой сервер (apache, caddy, traefik, haproxy-http, litespeed или произвольный regex):

```bash
sudo nano /etc/arxsentinel/config.yaml
sudo systemctl kill -s HUP arxsentinel   # перезагрузка без рестарта
```

---

### Debian / Ubuntu — ручная установка пакета

Скачайте `.deb` для своей архитектуры со страницы [Releases](https://github.com/mr-addams/arxsentinel/releases) и установите:

```bash
# amd64
sudo apt install ./arxsentinel_<version>_linux_amd64.deb

# arm64
sudo apt install ./arxsentinel_<version>_linux_arm64.deb
```

`apt install` автоматически подтянет зависимости (`fail2ban`), установит systemd unit, Fail2Ban filter/jail, logrotate и создаст системного пользователя `arxsentinel`.

После установки отредактируйте конфиг и запустите сервис:

```bash
sudo nano /etc/arxsentinel/config.yaml
sudo systemctl enable --now arxsentinel
```

### Fedora / RHEL / AlmaLinux / Rocky Linux

Скачайте `.rpm` для своей архитектуры со страницы [Releases](https://github.com/mr-addams/arxsentinel/releases) и установите:

```bash
# amd64
sudo dnf install ./arxsentinel_<version>_linux_amd64.rpm

# arm64
sudo dnf install ./arxsentinel_<version>_linux_arm64.rpm
```

`dnf install` автоматически подтянет зависимости, установит systemd unit в `/usr/lib/systemd/system/`, Fail2Ban filter/jail, logrotate и создаст системного пользователя `arxsentinel`.

После установки отредактируйте конфиг и запустите сервис:

```bash
sudo nano /etc/arxsentinel/config.yaml
sudo systemctl enable --now arxsentinel
```

> **RHEL 8 / CentOS Stream 8:** используйте `dnf` или `rpm -i` напрямую. Для Fail2Ban может потребоваться репозиторий EPEL:
> `sudo dnf install epel-release && sudo dnf install fail2ban`

### Arch Linux / Manjaro

Скачайте `.pkg.tar.zst` для своей архитектуры со страницы [Releases](https://github.com/mr-addams/arxsentinel/releases) и установите:

```bash
# amd64
sudo pacman -U arxsentinel_<version>_linux_amd64.pkg.tar.zst

# arm64
sudo pacman -U arxsentinel_<version>_linux_arm64.pkg.tar.zst
```

Пакет установит systemd unit в `/usr/lib/systemd/system/`, конфиги Fail2Ban, logrotate и создаст системного пользователя `arxsentinel`.

После установки отредактируйте конфиг и запустите сервис:

```bash
sudo nano /etc/arxsentinel/config.yaml
sudo systemctl enable --now arxsentinel
```

> **Fail2Ban на Arch:** установите перед или после arxsentinel: `sudo pacman -S fail2ban`

### Сборка из исходников

Требуется Go 1.19+:

```bash
git clone https://github.com/mr-addams/arxsentinel
cd arxsentinel
sudo ./scripts/install.sh
sudo systemctl enable --now arxsentinel
```

### Docker

Дистроблесс-образ (~12 МБ), запускается от пользователя с uid 65532, выставляет метрики Prometheus на `:9117`.

```bash
docker run -d \
  -v /var/log/nginx/access.log:/var/log/nginx/access.log:ro \
  -v /var/log/arxsentinel:/var/log/arxsentinel \
  -p 127.0.0.1:9117:9117 \
  ghcr.io/mr-addams/arxsentinel:latest
```

Подробнее: [README.docker.md](README.docker.md) — Docker Compose, монтирование томов, переменные окружения, интеграция с Fail2Ban.

### Kubernetes (Helm)

Топология DaemonSet — один под на узел, читает access.log через `hostPath`.

```bash
helm install arxsentinel ./deploy/helm/arxsentinel \
  --set logVolume.hostPath=/var/log/nginx \
  --set threatLog.hostPath=/var/log/arxsentinel
```

Подробнее: [README.helm.md](README.helm.md) — описание values, Prometheus Operator, деплой в облако.

## Конфигурация

Конфиг: `/etc/arxsentinel/config.yaml` (создаётся из `config.yaml` при установке).  
Переопределить путь: `ARXSENTINEL_CONFIG=/path/to/config.yaml`.

Ключевые параметры:

```yaml
general:
  log_file: /var/log/nginx/access.log   # лог-файл для наблюдения (пример nginx; см. также: streams:)
  stats_interval: 300s                  # период вывода STATS в operational.log

parser:
  # profile: "apache"  # укажите для не-nginx серверов: apache | caddy | traefik | haproxy-http | litespeed
  #                     # nginx combined log format работает без настройки профиля

scoring:
  alert_threshold: 50    # score → WARN в threat-лог
  ban_threshold: 80      # score → THREAT + Fail2Ban бан
  observation_window: 300s  # окно накопления/decay score

detectors:
  probe:
    enabled: true
    score: 25
    paths: [/.env, /.git/config, /wp-config.php, ...]  # список probe-путей

  rate:
    enabled: true
    threshold: 100   # запросов за window
    window: 60s
    score: 25

  useragent:
    enabled: true
    scanner_score: 40     # Nuclei, sqlmap, Nikto
    grabber_score: 20     # wget, HTTrack
    automation_score: 15  # python-requests, aiohttp
    empty_ua_score: 30

  bruteforce:
    enabled: true
    min_requests: 10
    ratio_threshold: 0.6  # >60% ответов 404
    score: 30

  crawler:
    enabled: true
    min_sequential: 5  # /page/1, /page/2, ... N подряд
    score: 20

  noasset:
    enabled: true
    min_page_requests: 3
    asset_ratio_threshold: 0.1  # <10% запросов к статике
    score: 20

  overflow:
    enabled: true
    max_url_length: 2048
    suspicious_params: [bypass, shell, cmd, exec, eval]
    score: 30

whitelist:
  fake_bot_score: 35      # штраф за UA легитимного бота без подтверждения DNS
  dns_verify_timeout: 2s  # таймаут DNS-верификации бота в pipeline
  custom:
    ips: [127.0.0.1]
    cidrs: [10.0.0.0/8]
    ua_substrings: [internal-monitor]

output:
  threat_log: /var/log/arxsentinel/threats.log
  operational_log: /var/log/arxsentinel/sentinel.log
```

> **Ограничение yaml.v3:** если в config.yaml указана секция (например, `scoring:`), она должна содержать **все** поля — иначе неуказанные обнулятся. Отсутствующие секции целиком берут Go-дефолты.

## Детекторы

| Детектор | Триггер | Дефолтный score |
|----------|---------|-----------------|
| **probe** | запрос к .env, .git, wp-config.php и др. | 25 за запрос |
| **rate** | >100 запросов за 60s | 25 |
| **useragent** | сканер/граббер/автоматизация/пустой UA | 15–40 |
| **bruteforce** | >60% ответов 404 при ≥10 запросах | 30 |
| **crawler** | ≥5 последовательных числовых URL (/page/1..N) | 20 |
| **noasset** | <10% запросов к статике при ≥3 страницах | 20 |
| **overflow** | URL >2048 символов или WAF bypass keywords | 30 |

Score накапливается с линейным decay за `observation_window`. При достижении `alert_threshold` — запись WARN, при `ban_threshold` — THREAT + Fail2Ban.

## Whitelist

Whitelist говорит ArxSentinel: «эти — свои, пропускай без проверки». Есть два независимых механизма: **автоматическая верификация ботов** (поисковые системы) и **кастомные исключения** (ваши IP, подсети, инструменты).

### Автоматическая верификация ботов (Googlebot, Bingbot, Яндекс и др.)

ArxSentinel знает User-Agent строки всех крупных поисковых ботов. Когда такой бот приходит, выполняется DNS-проверка подлинности:

1. Обратный DNS-запрос по IP → получаем hostname (например `crawl-66-249-66-1.googlebot.com`)
2. Прямой DNS по этому hostname → должен вернуть тот же IP
3. Hostname должен заканчиваться на один из известных доменов Google (`.googlebot.com`, `.google.com`)

Оба проверки прошли → бот легитимный → пропускается, очки не начисляются.  
Проверки не прошли → UA заявляет Googlebot, но IP не гугловский → начисляется штраф `fake_bot_score` (дефолт 35).

Встроенные верифицируемые боты: Google, Bing, Яндекс, DuckDuckBot, Baidu, Apple, GPTBot, ClaudeBot и другие — см. секцию `whitelist.bots` в `config.yaml`.

**Настройка не нужна** — верификация автоматическая. Результаты DNS кэшируются (`dns_cache.positive_ttl: 24h`), поэтому на производительность не влияет.

### Кастомный whitelist

Добавьте свои IP, подсети и инструменты в секцию `whitelist.custom`:

```yaml
whitelist:
  custom:
    ips:           []
    cidrs:         []
    ua_substrings: []
```

Запросы, совпавшие с любым пунктом, пропускаются **до** запуска детекторов — score не начисляется никогда.

---

#### `ips` — конкретные IP-адреса

Перечислите отдельные IP-адреса, которые никогда не проверяются.

```yaml
whitelist:
  custom:
    ips:
      - "192.168.1.50"    # рабочая станция в офисе
      - "10.99.99.1"      # сервер внутреннего мониторинга
      - "203.0.113.42"    # ваш домашний IP
```

Используйте для: своих серверов, известных партнёров, офисных машин, ноутбуков разработчиков.

---

#### `cidrs` — диапазоны IP-адресов (подсети)

CIDR — компактная запись диапазона IP-адресов. Вместо того чтобы перечислять сотни адресов, пишете одну строку.

Как читать: `192.168.1.0/24` означает «все адреса от `192.168.1.0` до `192.168.1.255`» — целый блок из 256 адресов. Число после `/` определяет размер блока:

| Запись | Диапазон | Адресов |
|--------|----------|---------|
| `10.0.0.1/32` | ровно `10.0.0.1` | 1 (один IP) |
| `192.168.1.0/24` | `192.168.1.0` – `192.168.1.255` | 256 |
| `10.0.0.0/8` | `10.0.0.0` – `10.255.255.255` | ~16 миллионов |

```yaml
whitelist:
  custom:
    cidrs:
      - "192.168.0.0/16"    # весь офис и VPN
      - "10.0.0.0/8"        # все приватные адреса 10.x.x.x
      - "172.16.0.0/12"     # Docker / внутренняя сеть
```

> **Как узнать свою подсеть?** Спросите системного администратора или посмотрите в сетевых настройках сервера. Хостинг-провайдеры обычно выдают блок вида `185.220.100.0/22` для вашего кластера.

Используйте для: офисных сетей, VPN-подсетей, диапазонов IP Cloudflare, CDN edge-узлов, вашего кластера серверов.

---

#### `ua_substrings` — подстроки User-Agent

Если запрос содержит эту строку где угодно в заголовке User-Agent — он попадает в whitelist. Сравнение **без учёта регистра**.

```yaml
whitelist:
  custom:
    ua_substrings:
      - "UptimeRobot"          # сервис мониторинга uptime
      - "internal-healthcheck" # ваш собственный скрипт проверки
      - "MySEOCrawler/"        # ваш SEO-инструмент
      - "Screaming Frog SEO"   # краулер Screaming Frog
      - "Ahrefs"               # бот Ahrefs
      - "Semrush"              # краулер SEMrush
```

> **Для SEO-инструментов:** если ваш SEO-краулер попадает под блокировку (делает много запросов или у него подозрительный UA), добавьте его название сюда. Точную UA-строку можно посмотреть в access.log:
> ```bash
> grep -i "screaming\|ahrefs\|semrush\|moz\|sitebulb" /var/log/nginx/access.log | awk -F'"' '{print $6}' | sort -u
> ```

**Достаточно подстроки** — полная строка не нужна. `"Ahrefs"` совпадёт с `"AhrefsBot/7.0"` и любой будущей версией.

---

### Применение изменений

Все изменения whitelist применяются **без перезапуска демона** — отправьте сигнал перезагрузки:

```bash
# Перезагрузить конфиг (whitelist, детекторы, пороги — всё кроме пути к лог-файлу)
systemctl kill -s HUP arxsentinel

# Или через PID-файл
kill -HUP $(cat /var/run/arxsentinel.pid)
```

Изменения вступают в силу в течение секунд. В operational-логе появится:

```
[CONFIG] reloaded: whitelist updated
```

### Полный пример

```yaml
whitelist:
  fake_bot_score: 35        # штраф за имитацию Googlebot/Bingbot
  dns_verify_timeout: "2s"  # таймаут DNS-верификации

  custom:
    ips:
      - "203.0.113.42"      # домашний IP разработчика
      - "10.99.99.1"        # мониторинг Zabbix

    cidrs:
      - "192.168.0.0/16"    # офис и VPN
      - "10.0.0.0/8"        # приватная сеть

    ua_substrings:
      - "UptimeRobot"
      - "Screaming Frog SEO Spider"
      - "AhrefsBot"
      - "SemrushBot"
      - "MJ12bot"           # краулер Majestic
```

## Архитектура

```
access.log (nginx / apache / caddy / traefik / haproxy / litespeed)
       │
  TailReader (inotify, logrotate-aware)
       │
  lines chan (буфер LinesBufSize)
       │
  whitelist.Matcher ──→ custom IP/CIDR/UA? → skip
       │
  whitelist.Verifier ──→ bot UA? → rDNS/fDNS → verified? → skip
       │                                      → fake bot? → +FakeBotScore
  tracker.Update(*IPState)
    ├── TotalRequests, Requests404
    ├── pathBuf (ring buffer, последние 64 пути)
    └── sliding window rate counters
       │
  scorer.Evaluate(ipState, entry)
    ├── decay накопленного score
    ├── запуск 7 детекторов
    └── вынесение вердикта (score → level)
       │
  output.ThreatLogger ──→ threats.log ──→ Fail2Ban ──→ iptables ban
                      └──→ sentinel.log (operational)
```

Фоновые горутины:
- **TailReader** — слежение за файлом через fsnotify, обработка mv/copytruncate logrotate
- **GC** — удаление неактивных IP каждые `gc_interval` (дефолт 60s)
- **Stats** — вывод `STATS processed/tracked/threats/suspicious` каждые `stats_interval`
- **SIGHUP listener** — конвертирует сигнал в канал для главного loop

## Мониторинг нескольких потоков

Запустите один процесс ArxSentinel, который наблюдает за несколькими лог-файлами одновременно — один конвейер на домен, полная изоляция.

### Конфигурация

```yaml
streams:
  - name: site1
    log_file: /var/log/nginx/site1.access.log
    threat_log: /var/log/arxsentinel/site1.threats.log
  - name: site2
    log_file: /var/log/apache2/site2.access.log
    threat_log: /var/log/arxsentinel/site2.threats.log
    profile: apache
```

> **Важно:** `streams:` и `general.log_file` взаимно исключают друг друга. Используйте одно или другое.

Каждый поток имеет собственный трекер, scorer, whitelist и лог угроз. Медленная атака или сбой в одном потоке не влияет на остальные.

### Обратная совместимость

Классическая конфигурация с `general.log_file` продолжает работать — она автоматически конвертируется в один безымянный поток (метка `stream=""` в Prometheus). Миграция конфига не требуется.

### Fail2Ban при нескольких потоках

Каждый поток записывает в свой `threat_log`. Создайте отдельную ловушку Fail2Ban для каждого файла:

```ini
# /etc/fail2ban/jail.d/arxsentinel-site1.conf
[arxsentinel-site1]
enabled  = true
filter   = arxsentinel
logpath  = /var/log/arxsentinel/site1.threats.log
maxretry = 1
bantime  = 86400

[arxsentinel-site2]
enabled  = true
filter   = arxsentinel
logpath  = /var/log/arxsentinel/site2.threats.log
maxretry = 1
bantime  = 86400
```

### Grafana

Дашборд включает переменную **Stream** для фильтрации панелей по потоку. Импортируйте `deploy/grafana/arxsentinel-dashboard.json` (v2).

---

## Логи

**Operational log** (`/var/log/arxsentinel/sentinel.log`) — рабочий лог демона:

```
2026-04-02 14:33:10 [STARTUP] arxsentinel v1.0.0 started
2026-04-02 14:33:12 [THREAT] 45.134.26.8 score=85 modules=probe,rate reason="..."
2026-04-02 14:38:10 [STATS] processed=14320 tracked=87 threats=3 suspicious=12
```

Теги: `STARTUP`, `SHUTDOWN`, `CONFIG`, `THREAT`, `WHITELIST`, `STATS`, `GC`, `ERROR`, `WARN`.  
Debug-теги (`PARSER`, `TAIL`, `DETECTOR`, `SCORER`) видны только при `logging.debug: true`.

**Threat log** (`/var/log/arxsentinel/threats.log`) — читает Fail2Ban:

```
2026-04-02T14:33:12Z THREAT 45.134.26.8 score=85 modules=probe,rate reason="probe:/.env,rate:142rps"
2026-04-02T14:35:01Z WARN   92.63.104.12 score=55 modules=useragent reason="ua:Nuclei/3.1.0"
```

Fail2Ban failregex: `THREAT <HOST> score=\d+` (файл `deploy/fail2ban/filter.d/arxsentinel.conf`).

## Управление

```bash
# Статус и логи
systemctl status arxsentinel
journalctl -u arxsentinel -f

# Перезагрузка конфига без перезапуска (SIGHUP)
kill -HUP $(cat /var/run/arxsentinel.pid)
# или
systemctl kill -s HUP arxsentinel

# Остановка (graceful — дренирует буфер строк)
systemctl stop arxsentinel

# Ручной бан/разбан через Fail2Ban
fail2ban-client status arxsentinel
fail2ban-client set arxsentinel unbanip 1.2.3.4
```

**Что обновляется при SIGHUP:** scorer (детекторы + пороги), whitelist matcher, debug/color флаги, пути к лог-файлам.  
**Что НЕ обновляется:** tracker (state IP), DNS cache, TailReader (путь к access.log требует перезапуска).

## JSON-формат логов

По умолчанию ArxSentinel парсит nginx combined log format (профиль не требуется) или формат, определённый активным профилем (apache, caddy, traefik, haproxy-http или litespeed).  
Поддерживается также JSON-формат — переключается через `config.yaml` без перекомпиляции.

Примеры ниже используют nginx. Для других серверов адаптируйте директиву `log_format` к вашему серверу.

### Шаг 1 — Настройка HTTP-сервера (пример nginx)

Добавьте нужный `log_format` в блок `http {}` файла `nginx.conf`.
Готовые конфиги также в [`deploy/examples/nginx-json-logformat.conf`](deploy/examples/nginx-json-logformat.conf).

**Прямой nginx (без прокси)** — `$remote_addr` содержит реальный IP клиента:

```nginx
log_format sentinel_json_direct escape=json
    '{'
        '"remote_addr":"$remote_addr",'
        '"time_iso8601":"$time_iso8601",'
        '"request":"$request",'
        '"status":"$status",'
        '"bytes_sent":"$bytes_sent",'
        '"http_referer":"$http_referer",'
        '"http_user_agent":"$http_user_agent"'
    '}';

access_log /var/log/nginx/access.log sentinel_json_direct;
```

**За обратным прокси** — настройте `ngx_http_realip_module` (см.
[Деплой за обратным прокси](#деплой-за-обратным-прокси)).
После обработки realip `$remote_addr` уже содержит реальный IP клиента,
поэтому тот же формат `sentinel_json_direct` работает без изменений — отдельный proxy-вариант не нужен.

### Шаг 2 — Обновить конфиг sentinel

```yaml
parser:
  log_format: "json"   # "combined" (по умолчанию) | "json"
```

Изменение вступает в силу после **SIGHUP** — рестарт не нужен:

```bash
kill -HUP $(cat /var/run/arxsentinel.pid)
```

### Кастомные имена полей

Если в вашем формате логов используются другие ключи — переопределите маппинг:

```yaml
parser:
  log_format: "json"
  json_fields:
    remote_addr: "client"
    time:        "ts"
    request:     "req"
    status:      "code"
    bytes_sent:  "size"
    referer:     "ref"
    user_agent:  "ua"
    real_ip:     "ip"
```

Неизвестные поля в JSON-строке игнорируются — потребляются только поля из маппинга.

## Деплой за обратным прокси

> **Внимание:** если HTTP-сервер стоит за прокси и реальный IP клиента настроен некорректно,
> ArxSentinel будет выставлять score **IP-адресу прокси**, а не реальному атакующему.
> Fail2Ban заблокирует ваш же прокси — сайт упадёт для всех.

### Как это работает

```
[Клиент 1.2.3.4] → [Прокси] → X-Forwarded-For: 1.2.3.4 → [HTTP-сервер]
                                                                   ↓
                                ngx_http_realip_module заменяет $remote_addr
                                первым не-доверенным IP из цепочки XFF
                                                                   ↓
                                                             access.log
                                                                   ↓
                                                            ArxSentinel
```

Модуль nginx `ngx_http_realip_module` читает `X-Forwarded-For` от доверенного прокси
и заменяет `$remote_addr` реальным IP клиента до того, как строка пишется в лог.
ArxSentinel читает `$remote_addr` из access.log — никакой дополнительной переменной не нужно.

### Готовые конфиги

Полные рабочие примеры для каждого прокси находятся в `deploy/examples/reverse-proxy/`:

| Прокси | Файлы |
|--------|-------|
| **HAProxy** | [`haproxy/haproxy.cfg`](deploy/examples/reverse-proxy/haproxy/haproxy.cfg), [`nginx.conf`](deploy/examples/reverse-proxy/haproxy/nginx.conf) |
| **Traefik** | [`traefik/traefik.yml`](deploy/examples/reverse-proxy/traefik/traefik.yml), [`nginx.conf`](deploy/examples/reverse-proxy/traefik/nginx.conf) |
| **Caddy** | [`caddy/Caddyfile`](deploy/examples/reverse-proxy/caddy/Caddyfile), [`nginx.conf`](deploy/examples/reverse-proxy/caddy/nginx.conf) |
| **nginx как RP** | [`nginx-rp/nginx-upstream.conf`](deploy/examples/reverse-proxy/nginx-rp/nginx-upstream.conf), [`nginx-origin.conf`](deploy/examples/reverse-proxy/nginx-rp/nginx-origin.conf) |

Каждый пример содержит конфиг прокси и конфиг origin-nginx с `set_real_ip_from`,
`real_ip_header X-Forwarded-For`, `real_ip_recursive on` и форматом лога `combined_realip`,
в котором `$remote_addr` используется как поле реального IP.

### Минимальный конфиг nginx (для любого прокси)

```nginx
http {
    # Укажите реальный IP или CIDR вашего прокси.
    # Docker Compose: 172.16.0.0/12    Один хост: 127.0.0.1
    set_real_ip_from  <ip-или-cidr-прокси>;

    # Все основные прокси (HAProxy, Traefik, Caddy, nginx) выставляют X-Forwarded-For.
    real_ip_header    X-Forwarded-For;

    # Проходим по цепочке XFF — берём первый не-доверенный IP как реальный клиент.
    real_ip_recursive on;

    # После обработки realip $remote_addr — это и есть реальный IP клиента.
    log_format combined_realip
        '$remote_addr - $remote_user [$time_local] '
        '"$request" $status $body_bytes_sent '
        '"$http_referer" "$http_user_agent" "$remote_addr"';

    server {
        access_log /var/log/nginx/access.log combined_realip;
        ...
    }
}
```

### Cloudflare

Если nginx стоит напрямую за Cloudflare — используйте `CF-Connecting-IP` вместо `X-Real-IP`
(Cloudflare проставляет этот заголовок на своём edge; `X-Forwarded-For` может быть подделан клиентом).

Сгенерируйте директивы `set_real_ip_from` для всех CIDR-диапазонов Cloudflare:

```bash
sudo scripts/update-cloudflare-ips.sh /etc/nginx/cloudflare-real-ip.conf
```

Добавьте в `nginx.conf`:

```nginx
http {
    include /etc/nginx/cloudflare-real-ip.conf;  # set_real_ip_from для всех CF-диапазонов
    real_ip_header CF-Connecting-IP;
    ...
}
```

**Автообновление диапазонов** (Cloudflare обновляет их периодически):

```bash
# Добавить в cron — каждый понедельник в 03:00
0 3 * * 1 /path/to/update-cloudflare-ips.sh /etc/nginx/cloudflare-real-ip.conf && nginx -t && nginx -s reload
```

## Конфигурации для CMS

Готовые переопределения `probe.paths` для наиболее популярных PHP-стеков находятся в
`deploy/examples/cms/`. Скопируйте нужные пути в свой `config.yaml`:

| Файл | Для кого |
|------|----------|
| [`wordpress.yaml`](deploy/examples/cms/wordpress.yaml) | WordPress — `wp-login.php`, `xmlrpc.php`, перечисление пользователей через REST |
| [`laravel.yaml`](deploy/examples/cms/laravel.yaml) | Laravel — `.env`, `/storage/`, `/vendor/`, Telescope, Horizon |
| [`drupal.yaml`](deploy/examples/cms/drupal.yaml) | Drupal — `/user/login`, `settings.php`, `update.php` |
| [`joomla.yaml`](deploy/examples/cms/joomla.yaml) | Joomla — `/administrator/`, `configuration.php` |
| [`generic-php.yaml`](deploy/examples/cms/generic-php.yaml) | Custom PHP — phpinfo, phpMyAdmin, Adminer, резервные копии |

**Как применить конфиг CMS:**

1. Откройте `deploy/examples/cms/<cms>.yaml` и скопируйте список `paths:`.
2. Вставьте его в `config.yaml` под `detectors.probe.paths:`.
3. Перезагрузите без рестарта: `kill -HUP $(pgrep arxsentinel)` — или `systemctl kill -s HUP arxsentinel`.

Пути **дополняют** (а не заменяют) встроенный список sensitive-путей по умолчанию.
Чтобы использовать только свой список, задайте в `detectors.probe.paths:` ровно те пути, которые нужны.

## Произвольный формат логов (regex)

Используйте любой текстовый формат логов, указав Go-регулярное выражение с именованными группами.

```yaml
parser:
  log_format: "regex"
  regex_pattern: '(?P<remote_addr>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<request>[^"]*)" (?P<status>\d+) (?P<bytes_sent>\d+) "(?P<http_referer>[^"]*)" "(?P<http_user_agent>[^"]*)"'
```

### Именованные группы

| Группа | Обязательная | Описание |
|--------|-------------|----------|
| `remote_addr` | ✅ | IP-адрес клиента или прокси |
| `time` | ✅ | Время запроса (формат `02/Jan/2006:15:04:05 -0700`) |
| `request` | ✅ | Строка запроса: `METHOD /path HTTP/x.x` |
| `status` | ✅ | HTTP-код ответа |
| `bytes_sent` | ✅ | Размер ответа в байтах |
| `http_referer` | опциональная | Значение заголовка Referer |
| `http_user_agent` | опциональная | Значение заголовка User-Agent |
| `real_ip` | опциональная | Реальный IP клиента из заголовка доверенного прокси |

Отсутствующие опциональные группы дают пустые поля — sentinel продолжает работу.

### Пример: HAProxy HTTP log

```yaml
parser:
  log_format: "regex"
  regex_pattern: '(?P<remote_addr>\S+):\d+ \S+ \S+/\S+ \d+/\d+/\d+/\d+/\d+ (?P<status>\d+) (?P<bytes_sent>\d+) .* "(?P<request>[^"]*)"'
```

### Типичные ошибки

- **Отсутствует обязательная группа** — sentinel завершается при старте с понятным сообщением об ошибке.
- **Неверный формат времени** — поддерживается только `02/Jan/2006:15:04:05 -0700` (nginx `$time_local`). ISO 8601 не парсится; детекторы без временны́х зависимостей работают в любом случае.

---

## Prometheus-метрики

Включить в `config.yaml`:

```yaml
metrics:
  enabled: true
  listen_addr: ":9117"   # порт HTTP-сервера метрик
  # Опциональная basic auth — оставьте username пустым для отключения:
  username: ""
  password_hash: ""      # bcrypt-хеш; генерацию см. в deploy/grafana/README.md
```

### Эндпоинты

| Эндпоинт | Авторизация | Описание |
|----------|-------------|----------|
| `/metrics` | опциональная basic auth | Scrape-эндпоинт Prometheus |
| `/health` | нет | Liveness probe — всегда возвращает `200 {"status":"ok"}` |

`/health` не требует учётных данных и безопасно открывается для балансировщиков,
Docker `HEALTHCHECK` и k8s liveness/readiness probes.

### Доступные метрики

| Метрика | Тип | Описание |
|---------|-----|----------|
| `arxsentinel_lines_processed_total` | Counter | Обработано строк лога |
| `arxsentinel_threats_total{level}` | Counter | Угрозы по уровню (`THREAT` / `WARN`) |
| `arxsentinel_detector_hits_total{detector}` | Counter | Срабатывания по детектору |
| `arxsentinel_tracked_ips` | Gauge | Текущее количество отслеживаемых IP |
| `arxsentinel_suspicious_ips` | Gauge | IP с score выше alert threshold |

### Конфиг scrape для Prometheus

```yaml
scrape_configs:
  - job_name: "arxsentinel"
    static_configs:
      - targets: ["localhost:9117"]
    # basic_auth:          # только если авторизация включена в конфиге sentinel
    #   username: "prometheus"
    #   password: "ваш-пароль-открытым-текстом"
```

Настройка дашборда Grafana — в [`deploy/grafana/README.md`](deploy/grafana/README.md).

---

## Решение проблем

**Демон не запускается — ошибка threat log:**  
Проверьте права на `/var/log/arxsentinel/` — директория должна принадлежать пользователю `arxsentinel`.

**Fail2Ban не банит — проверьте формат лога:**  
```bash
fail2ban-regex /var/log/arxsentinel/threats.log /etc/fail2ban/filter.d/arxsentinel.conf
```

**Слишком много ложных WARN — снизьте чувствительность:**  
Уменьшите `score` или повысьте пороги (`threshold`, `ratio_threshold`) в конфиге, затем `kill -HUP`.

**Отладка pipeline — включите debug-режим:**  
```yaml
logging:
  debug: true
```
Перезапустите или `kill -HUP`. В operational.log появятся строки `[PARSER]`, `[DETECTOR]`, `[SCORER]` на каждый запрос.

**Высокое потребление памяти:**  
Уменьшите `state.max_tracked_ips` (дефолт 100000; каждый IP ≈ 2.5 KB → 100k ≈ 250 MB).

---

[English documentation → README.md](README.md) | [Українська документація → README.uk.md](README.uk.md)
