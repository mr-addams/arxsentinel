# ArxSentinel

[![Release](https://img.shields.io/github/v/release/mr-addams/arxsentinel?include_prereleases&label=release)](https://github.com/mr-addams/arxsentinel/releases)
[![Build](https://github.com/mr-addams/arxsentinel/actions/workflows/release.yml/badge.svg)](https://github.com/mr-addams/arxsentinel/actions/workflows/release.yml)
[![License](https://img.shields.io/badge/license-Elastic--2.0-blue)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go)](go.mod)
[![Platforms](https://img.shields.io/badge/linux-amd64%20%7C%20arm64%20%7C%20arm%2Fv7%20%7C%20riscv64%20%7C%20i386-lightgrey?logo=linux)](https://github.com/mr-addams/arxsentinel/releases)
[![FreeBSD](https://img.shields.io/badge/freebsd-386%20%7C%20amd64%20%7C%20arm%20%7C%20arm64-red?logo=freebsd)](https://github.com/mr-addams/arxsentinel/releases)
[![Packages](https://img.shields.io/badge/packages-deb%20%7C%20rpm%20%7C%20pacman-blue)](https://github.com/mr-addams/arxsentinel/releases)

> 🌐 [English](README.md) | [Українська документація](README.uk.md) | 📖 [Кулинарная книга конфигураций](cookbook/CookBook.ru.md)

**Распределённый пайплайн обработки событий безопасности для любого HTTP-сервера** — от одного nginx VPS до флота узлов.  
~12 МБ RAM · единый бинарник · без зависимостей в runtime · расширяется через exec+JSON-плагины на любом языке.  
Собирайте события на одной машине, скорируйте на другой, баньте на третьей — через встроенную шифрованную сетку узлов (QUIC · TLS 1.3 · Ed25519 · TOFU). Без Redis, без Kafka, без VPN. → [Руководство по распределённой обработке](docs/DISTRIBUTED.ru.md)

> **Лицензия:** ArxSentinel распространяется по [Elastic License 2.0](LICENSE). Бесплатное использование для собственной инфраструктуры. Коммерческое использование в качестве управляемого сервиса безопасности или телеметрии, а также в составе управляемого сервиса, требует отдельного соглашения. Подробности — в файле [LICENSE](LICENSE).

> **Построен на [arx-core](https://github.com/mr-addams/arx-core).** Движок пайплайна ArxSentinel,
> система плагинов (Source/Sink/Detector/Processor/Executor) и NCS-мост работают на базе
> [arx-core](https://github.com/mr-addams/arx-core/blob/v0.1.0/README.md) — универсального потоково-ориентированного
> фреймворка телеметрии. Жизненный цикл движка, runtime-контракт и базовые интерфейсы плагинов
> живут в [`arx-core/docs/`](https://github.com/mr-addams/arx-core/tree/v0.1.0/docs)
> (`architecture.md`, `contract.md`, `plugin-development.md`). Этот README описывает
> продуктовый слой ArxSentinel: детекторы безопасности, скоринг угроз, разводку NCS и
> Cloudflare/MikroTik/OpenWrt/OPNsense/nginx-экзекуторы. См. [Архитектура](docs/ARCHITECTURE.md) для разделения.

```
  ╔══════════════════════════════════════════════════════════════════╗
  ║  SOURCES                                                         ║
  ║  nginx · Apache · Caddy · Traefik · HAProxy · LiteSpeed          ║
  ║  file │ stdin │ syslog │ http (push/pull · Firehose/Loki/OTLP)   ║
  ║  exec+JSON plugin (любой язык)                                   ║
  ╚═══════════════════════════╤══════════════════════════════════════╝
                              │ разобранные записи лога
  ╔═══════════════════════════╧══════════════════════════════════════╗
  ║  PROCESSORS                                                      ║
  ║                                                                  ║
  ║  Whitelist ── свои IP/CIDR/UA · DNS-верификация ботов            ║
  ║  ChainGuard ─ проверка целостности цепочки IP за прокси          ║
  ║  WAF rule-engine (processors: · pass / drop / tag)               ║
  ║                                                                  ║
  ║  Детекторы (встроенные)   Детекторы (плагины)                    ║
  ║  ├─ probe      score 25  └─ exec+JSON detector (любой язык)      ║
  ║  ├─ bruteforce score 30                                          ║
  ║  ├─ crawler    score 20                                          ║
  ║  ├─ noasset    score 20                                          ║
  ║  ├─ rate       score 25                                          ║
  ║  ├─ useragent  score 40/20/15                                    ║
  ║  ├─ overflow   score 30                                          ║
  ║  └─ badbot     score 60                                          ║
  ║                                                                  ║
  ║  Scorer ── накапливает score → WARN (≥50) │ THREAT (≥80)         ║
  ╚═══════════════════════════╤══════════════════════════════════════╝
                              │ события угроз
  ╔═══════════════════════════╧══════════════════════════════════════╗
  ║  SINKS  (пассивное логирование)                                  ║
  ║  file (формат fail2ban) · stdout JSON · exec+JSON plugin         ║
  ║  Grafana Loki · Splunk HEC · Datadog Logs API  (форвардинг в SIEM)║
  ╚═══════════════════════════╤══════════════════════════════════════╝
                              │ sentinel-threat sink → AttachWriter()
  ╔═══════════════════════════╧══════════════════════════════════════╗
  ║  NAMED CHANNEL SWITCH  (очередь Point-to-Point)                  ║
  ║  memory │ bbolt (file) │ redis │ transport (QUIC-сетка узлов)    ║
  ╚═══════════════════════════╤══════════════════════════════════════╝
                              │ ncs://<channel-name> → AttachReader()
  ╔═══════════════════════════╧═══════════════════════════════════════════════════════════════════════╗
  ║  EXECUTORS  (активный ответ — опционально)                                                        ║
  ║  Cloudflare IP Lists · MikroTik address-list · nginx blocklist · OpenWrt ipset · OPNsense alias   ║
  ╚═══════════════════════════════════════════════════════════════════════════════════════════════════╝
```

## Сценарии использования

ArxSentinel масштабируется от классического bare-metal VPS до распределённого Kubernetes-кластера — каждый сценарий ниже — это самодостаточная стартовая точка.

### 1. Классическая защита веб-сервера — nginx + Fail2Ban

Один конфиг, никакой дополнительной настройки. Работает из коробки:

```yaml
general:
  log_file: /var/log/nginx/access.log
output:
  threat_log: /var/log/arxsentinel/threats.log
```

### 2. Docker Compose sidecar

Примонтируйте том логов nginx; ArxSentinel будет читать их как sidecar. Смотрите [`deploy/examples/docker/`](deploy/examples/docker/):

```yaml
# docker-compose.yml — выдержка
services:
  arxsentinel:
    image: ghcr.io/mr-addams/arxsentinel:latest
    volumes:
      - nginx_logs:/var/log/nginx:ro
    environment:
      ARXSENTINEL_LOG_FILE: /var/log/nginx/access.log
```

### 3. Kubernetes DaemonSet

Один под на узел, читает логи хоста через `hostPath`. Смотрите [`deploy/examples/kubernetes/`](deploy/examples/kubernetes/) и [Helm README](deploy/container/k8s/arxsentinel/README.md):

```bash
helm install arxsentinel ./deploy/container/k8s/arxsentinel \
  --set logVolume.hostPath=/var/log/nginx
```

### 4. Агрегация нескольких серверов

Наблюдайте за несколькими серверами в одном процессе — полная изоляция IP-состояния на поток:

```yaml
streams:
  - name: frontend
    log_file: /var/log/nginx/access.log
  - name: api
    log_file: /var/log/apache2/api.log
    profile: apache
```

Когда логи живут на *разных машинах* — не монтируйте и не пересылайте их:
запустите 12-мегабайтный коллектор рядом с каждым логом и пробрасывайте
события через встроенную шифрованную сетку (см. [сценарий 8](#8-распределённый-пайплайн--собирай-где-угодно-детектируй-централизованно-бань-на-границе)).

### 5. Произвольный формат логов

API gateway, логи пользовательского приложения, любой текстовый формат — предоставьте regex с именованными группами:

```yaml
parser:
  log_format: "custom"
  custom_regex: '(?P<ip>\S+) \S+ \S+ \[.*?\] "\S+ (?P<path>\S+) \S+" (?P<status>\d+) (?P<size>\d+) "(?P<ua>[^"]*)"'
```

### 6. Плагин-детектор через exec+JSON

Любой скрипт или бинарник как дополнительный детектор; вызывается для каждого запроса через stdin/stdout на любом языке. Смотрите [Разработка плагинов](#разработка-плагинов):

```yaml
detectors:
  plugins:
    - name: ml-classifier
      exec: /opt/plugins/classify.py
      score: 45
```

### 7. Пользовательский output sink — exec+JSON

Маршрутизируйте угрозы в любое место — SIEM, webhook, Telegram, пользовательский скрипт:

```yaml
sinks:
  - type: exec
    exec: /opt/plugins/send-to-siem.sh
```

### 8. Observability — форвардинг в Loki / Splunk / Datadog

Отправляйте скорированные события угроз напрямую в вашу log-платформу как
sink первого класса — удобно, когда у вас уже есть SIEM и ArxSentinel нужен
как фид рядом (или вместо) Fail2Ban/executor-респондеров. JSON-конверт
рекомендуется для читаемости в log-платформе:

```yaml
sinks:
  - type: loki
    format: json
    loki_url: https://loki.example.com:3100
    loki_labels:
      job: arxsentinel
```

Та же форма работает для `type: splunk` (HEC JSON-эндпоинт — нужны
`splunk_url` + `splunk_token`) и `type: datadog` (Logs API v2 — нужен
`datadog_url` с регионом, например `https://http-intake.logs.datadoghq.com`,
плюс `datadog_api_key`). TLS, mTLS, батчинг, gzip и поля мульти-тенантности
доступны per sink — см. [docs/providers/observability/](docs/providers/observability/).
Quick-start рецепты: [cookbook/observability/](cookbook/observability/).

### 9. Распределённый пайплайн — собирай где угодно, детектируй централизованно, бань на границе

Один и тот же бинарник становится **коллектором**, **детектором** или
**респондером** только через конфиг, соединяясь по встроенной взаимно
аутентифицированной QUIC-сетке — без брокера сообщений, без log shipper'а,
без VPN:

```
  Pi / VPS / NAS коллекторы          машина детекции              enforcement
 ┌────────────┐
 │ логи nginx  │──┐   "edge-raw"   ┌───────────────┐  "scored"  ┌───────────────────────────────────────┐
 └────────────┘  ├──────────────▶│ 8 детекторов · │──────────▶│ MikroTik · OpenWrt · OPNsense · nginx │
 ┌────────────┐  │  QUIC/TLS 1.3  │ WAF · скоринг  │            │ CF WAF · SIEM                         │
 │ логи API    │──┘   Ed25519+TOFU └───────────────┘            └───────────────────────────────────────┘
 └────────────┘
```

```yaml
# узел-коллектор — только парсинг, проброс без скоринга (12 МБ, работает на Pi)
streams:
  - pipelines:
      - raw_forward: true
        inputs:  [{type: file, path: /var/log/nginx/access.log}]
        outputs: [{type: sentinel-threat, name: edge-raw, format: raw-line,
                   queue: {type: transport, mode: send, peer: "brain:4097"}}]
```

Атакующий, прощупывающий несколько ваших сервисов, накапливает **один
суммарный score** на узле-детекторе — и получает бан везде одновременно.
Полное руководство оператора с 5 готовыми топологиями (хоумлаб →
корпоративный поток в SIEM):
**[docs/DISTRIBUTED.ru.md](docs/DISTRIBUTED.ru.md)** · рецепты:
[cookbook/distributed-ncs/](cookbook/distributed-ncs/README.md) — каждая
топология проверена CI на реальных контейнерах.

---

## Быстрый старт

Устанавливает пакет, включает systemd-сервис и сразу работает с nginx:

```bash
curl -fsSL https://raw.githubusercontent.com/mr-addams/arxsentinel/main/scripts/get.sh | sudo bash
```

Отредактируйте конфиг для вашего сервера, затем перезагрузитесь без рестарта:

```bash
sudo nano /etc/arxsentinel/config.yaml
sudo systemctl kill -s HUP arxsentinel
```

Для Docker, Kubernetes и других методов установки — смотрите [Установка](#установка) ниже.

---

## Установка

### Быстрая установка — любой дистрибутив (рекомендуется)

Автоматически определяет дистрибутив и архитектуру, загружает правильный пакет из GitHub Releases,
устанавливает его менеджером пакетов вашей системы, включает и запускает сервис:

```bash
curl -fsSL https://raw.githubusercontent.com/mr-addams/arxsentinel/main/scripts/get.sh | sudo bash
```

Работает на Debian, Ubuntu, Fedora, RHEL, AlmaLinux, Rocky Linux и Arch Linux.
Требует `curl` и `sudo`. Fail2Ban устанавливается автоматически, если отсутствует.

Сервис запускается сразу и работает с nginx из коробки — никаких профилей не нужно. Чтобы переключиться на другой сервер (apache, caddy, traefik, haproxy-http, litespeed или произвольный regex):

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

# arm/v7
sudo apt install ./arxsentinel_<version>_linux_armv7.deb

# riscv64
sudo apt install ./arxsentinel_<version>_linux_riscv64.deb

# i386
sudo apt install ./arxsentinel_<version>_linux_386.deb
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

# arm/v7
sudo dnf install ./arxsentinel_<version>_linux_armv7.rpm

# riscv64
sudo dnf install ./arxsentinel_<version>_linux_riscv64.rpm

# i386
sudo dnf install ./arxsentinel_<version>_linux_386.rpm
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

# arm/v7
sudo pacman -U arxsentinel_<version>_linux_armv7.pkg.tar.zst

# riscv64
sudo pacman -U arxsentinel_<version>_linux_riscv64.pkg.tar.zst

# i386
sudo pacman -U arxsentinel_<version>_linux_386.pkg.tar.zst
```

Пакет установит systemd unit в `/usr/lib/systemd/system/`, конфиги Fail2Ban, logrotate и создаст системного пользователя `arxsentinel`.

После установки отредактируйте конфиг и запустите сервис:

```bash
sudo nano /etc/arxsentinel/config.yaml
sudo systemctl enable --now arxsentinel
```

> **Fail2Ban на Arch:** установите перед или после arxsentinel: `sudo pacman -S fail2ban`

### FreeBSD

Скрипт `get.sh` выше не подходит (он рассчитан только на Linux-дистрибутивы с `/etc/os-release`). Скачайте архив `freebsd_<arch>` со страницы [Releases](https://github.com/mr-addams/arxsentinel/releases) и запустите установщик из архива:

```sh
fetch https://github.com/mr-addams/arxsentinel/releases/latest/download/arxsentinel_<version>_freebsd_<arch>.tar.gz
tar xzf arxsentinel_<version>_freebsd_<arch>.tar.gz
cd arxsentinel_<version>_freebsd_<arch>
sudo sh install.sh
```

`install.sh` создаёт системного пользователя `arxsentinel`, устанавливает бинарник и rc.d-сервис, сидирует конфиг из встроенного примера (при повторном запуске существующий конфиг не перезаписывается). Включить и запустить:

```sh
sysrc arxsentinel_enable=YES
service arxsentinel start
```

Полное руководство — структура путей на FreeBSD, управление rc.d-сервисом и запуск веб-сервера в `podman` на FreeBSD (драйвер хранилища, настройка firewall, особенности контейнерной сети): [FreeBSD Deployment Cookbook](cookbook/freebsd/CookBook.ru.md).

### Сборка из исходников

Требуется Go 1.26+:

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

Подробнее: [README.docker.md](deploy/container/docker/README.md) — Docker Compose, монтирование томов, переменные окружения, интеграция с Fail2Ban.

### Kubernetes (Helm)

Топология DaemonSet — один под на узел, читает access.log через `hostPath`.

```bash
helm install arxsentinel ./deploy/container/k8s/arxsentinel \
  --set logVolume.hostPath=/var/log/nginx \
  --set threatLog.hostPath=/var/log/arxsentinel
```

Подробнее: [Helm README](deploy/container/k8s/arxsentinel/README.md) — описание values, Prometheus Operator, деплой в облако.

## Поддерживаемые HTTP-серверы

### Таблица совместимости

| Сервер | Профиль | Требуемая настройка |
|--------|---------|---------------------|
| nginx | *(по умолчанию — профиль не нужен)* | Нет — nginx combined log format работает из коробки |
| Apache | `apache` | Нет — стандартный CLF |
| Traefik | `traefik` | Добавьте `fields.headers.names.User-Agent/Referer: keep` в accessLog — смотрите [`deploy/examples/traefik/`](deploy/examples/traefik/) |
| LiteSpeed / OpenLiteSpeed | `litespeed` | Нет — стандартный CLF |
| Caddy | `caddy` | [xcaddy](https://github.com/caddyserver/xcaddy) + плагин [transform-encoder](https://github.com/caddyserver/transform-encoder) — смотрите [`deploy/examples/caddy/`](deploy/examples/caddy/) |
| HAProxy | `haproxy-http` | `http-request capture` + пользовательский `log-format` с UA — смотрите [`deploy/examples/haproxy/`](deploy/examples/haproxy/) |

> В каждом релизе публикуется таблица **Tested product versions** с точными версиями серверов, на которых валидировалась сборка — смотрите [GitHub Releases](https://github.com/mr-addams/arxsentinel/releases).

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

> **Замечание — LiteSpeed / OpenLiteSpeed:** Оба сервера (LSWS и OLS) по умолчанию пишут Apache CLF —
> настройка формата лога не требуется. Путь логов: `/usr/local/lsws/logs/access.log`
> (server-wide) или `/usr/local/lsws/logs/<vhostname>/access.log` (per virtual host).
> Если сервер работает за reverse proxy, включите "Use Client IP in Header" в WebAdmin, чтобы реальный IP клиента писался
> в `%h` напрямую. Смотрите `deploy/examples/litespeed/` для полного конфига.

> **Замечание — Caddy:** Встроенный JSON-энкодер Caddy v2 выводит вложенные объекты. Профиль
> `caddy` требует плагина
> [caddy-transform-encoder](https://github.com/caddyserver/transform-encoder)
> для вывода в формате CLF. Смотрите `deploy/examples/caddy/Caddyfile` для настройки.

## Возможности

- **8 детекторов:** probe-сканирование, rate-аномалия, подозрительный User-Agent, bruteforce (404 ratio), sequential crawler, no-asset bot, URL overflow / WAF bypass, community bad-bot blocklist
- **Chain Guard:** обнаруживает IP-адреса Cloudflare/CDN и bogon/RFC 1918/CGNAT в позиции client IP — сигнализирует о неправильно настроенной цепочке прокси до того, как детекторы ArxSentinel потеряют способность определять реальных атакующих
- **DNS-верификация ботов:** Googlebot, Bingbot, Yandex, DuckDuckGo и другие верифицируются по rDNS/fDNS — легитимные краулеры в бан не попадают
- **Multi-stream + Multi-pipeline:** несколько лог-файлов в одном процессе; внутри каждого потока — независимые pipeline с собственными детекторами, источниками, sink'ами и трекером IP-состояния (или общий трекер через `tracker_group`)
- **Observability-sink'и:** пробрасывайте события угроз в Grafana Loki, Splunk HEC или Datadog Logs API — форвардинг в SIEM как альтернатива (или дополнение) к респондерам Fail2Ban/executor
- **Распределённый пайплайн (Distributed NCS):** растяните pipeline на несколько машин через встроенную шифрованную сетку узлов (QUIC · TLS 1.3 · Ed25519-идентичность · TOFU-пиннинг) — пробрасывайте сырые распарсенные записи на центральный детектор или скорированные вердикты на удалённые респондеры; без брокера, без log shipper'а, без VPN. См. [docs/DISTRIBUTED.ru.md](docs/DISTRIBUTED.ru.md)
- **Whitelist:** IP, CIDR, UA-подстроки — конфигурируемые списки исключений
- **Линейный decay score:** очки затухают за `observation_window`, нет ложных банов от старого трафика
- **Prometheus-метрики:** `/metrics` на настраиваемом порту (по умолчанию `:9117`), опциональная basic auth с bcrypt; дашборд Grafana в комплекте
- **Health endpoint:** `/health` всегда возвращает `200 {"status":"ok"}` без авторизации — готов для Docker `HEALTHCHECK`, k8s probes и балансировщиков
- **JSON-формат логов:** переключение на JSON-парсинг через `parser.log_format: "json"` без перекомпиляции
- **SIGHUP reload:** конфиг, scorer, парсер и whitelist пересоздаются без перезапуска демона
- **Graceful shutdown:** дренирование буфера строк при SIGTERM
- **Systemd + logrotate + Fail2Ban:** готовые deploy-конфиги в комплекте

## Требования

- Linux amd64 / arm64 / arm/v7 / riscv64 / i386 с systemd, **либо** FreeBSD 386 / amd64 / arm / arm64 с rc.d
- Fail2Ban
- HTTP-сервер, пишущий access.log в поддерживаемом формате (nginx, Apache, Caddy, Traefik, HAProxy, LiteSpeed, OpenLiteSpeed — или произвольный regex)

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

  badbot:
    enabled: true
    score: 60
    check_ua: true
    check_referrer: false   # opt-in: проверять также заголовок Referer (~7108 паттернов)

blocklist:
  storage: ""              # "" = только в памяти; путь к файлу = bbolt (сохраняется между запусками)
  lists:
    - name: badbot-ua
      refresh_interval: 24h
      sources:
        - url: "https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/master/_generator_lists/bad-user-agents.list"
          format: plain_text
    - name: badbot-ref
      refresh_interval: 24h
      sources:
        - url: "https://raw.githubusercontent.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/master/_generator_lists/bad-referrer-words.list"
          format: plain_text

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
| **badbot** | UA (или Referer) совпадает с community-blocklist (~685 паттернов) | 60 |

Score накапливается с линейным decay за `observation_window`. При достижении `alert_threshold` — запись WARN, при `ban_threshold` — THREAT + Fail2Ban.

## Процессор-плагины

Процессоры запускаются до цепочки детекторов. Они могут коротко замкнуть pipeline (пропустить), полностью отбросить событие или пометить его для последующего скоринга.

| Плагин | Описание |
|--------|----------|
| `whitelist` | IP/CIDR/path/UA allowlist — коротко замыкает pipeline |
| `chaincheck` | Проверяет целостность цепочки IP за обратным прокси |
| `waf` | Правило-движок — pass / drop / tag с интеграцией в scorer |

## Развёртывание

### systemd — bare metal

Полностью охватывается установщиками пакетов выше. Используйте `systemctl` для управления сервисом и `kill -HUP` для live reload. Смотрите [Управление](#управление) для полного справочника команд.

### FreeBSD — rc.d

Охватывается FreeBSD-установщиком выше. Используйте `service arxsentinel <start|stop|status>` для управления сервисом; `sysrc arxsentinel_enable=YES` включает автозапуск при перезагрузке. Полное руководство, включая запуск веб-сервера в `podman` на FreeBSD: [FreeBSD Deployment Cookbook](cookbook/freebsd/CookBook.ru.md).

### Docker Compose

ArxSentinel работает как sidecar рядом с HTTP-сервером, читая общие тома логов.
Готовые Compose файл и конфиг: [`deploy/examples/docker/`](deploy/examples/docker/).
Полное руководство Docker: [README.docker.md](deploy/container/docker/README.md).

### Kubernetes

DaemonSet (один под на узел, читает логи хоста) или sidecar (читает из emptyDir, шарёного с контейнером приложения).
Готовые манифесты: [`deploy/examples/kubernetes/`](deploy/examples/kubernetes/).
Helm-чарт с описанием values: [Helm README](deploy/container/k8s/arxsentinel/README.md).

## Исполнители

Исполнители — это плагины с состоянием, которые выполняются после оценки угроз. В отличие от Sink (пассивная запись в лог), исполнители активно управляют внешними ресурсами: ведут локальный dedup-словарь, применяют TTL-истечение и собирают статистику.

> **Заметка о терминах:** «Executor» / «Исполнитель» — термин уровня плагина/конфига (`executors:` в YAML, `pkg/executorplugins/*` в коде) — используется во всём README и коде. В топологии [Distributed NCS](docs/DISTRIBUTED.ru.md) узел, который запускает исполнители, называется **Responder** (в паре с **Collector** и **Detector** — три роли узлов). Это те же плагины, просто другая терминология для описания *где* они выполняются в multi-node развёртывании.

| Исполнитель | Пакет | Описание |
|---|---|---|
| **cloudflare** | `pkg/executor/cloudflare` | Добавляет угрожающие IP в Cloudflare IP List; автоматически удаляет устаревшие записи через TTL sweep |
| **nginx** | `pkg/executor/nginx` | Записывает заблокированные IP в обычный файл блокировки (TTL автовыпадения, атомарные записи, опциональная команда перезагрузки); вы подключаете файл в nginx как вам удобнее |
| **mikrotik** | `pkg/executor/mikrotik` | Управляет list адресов файервола RouterOS v7 через REST API; TTL-автоответ, удаляет только записи, созданные arxsentinel, совместим с CHR/ARM |
| **openwrt** | `pkg/executor/openwrt` | Управляет nftables ipset через ubus-эндпоинт роутера (uhttpd-mod-ubus) с использованием стандартных rpcd-объектов `uci`/`rc`; батч-правка UCI + один reload за цикл, TTL считает сам плагин (не native nftables) |
| **opnsense** | `pkg/executor/opnsense` | Управляет алиасом файервола через REST API OPNsense (`alias_util` add/delete/list); независимый point add/delete на событие (без батчинга — API применяет изменения немедленно), TTL считает сам плагин через активный sweep |

Подробнее: [docs/executors.md](docs/executors.md) — обзор фреймворка и добавление собственных исполнителей.
Подробнее: [docs/executor-cloudflare.md](docs/executor-cloudflare.md) — конфигурация и устранение неполадок Cloudflare.
Подробнее: [docs/executor-nginx.md](docs/executor-nginx.md) — исполнитель nginx blocklist.

## Недавно доставленные функции

- **Поддержка FreeBSD** — нативные сборки `386`/`amd64`/`arm`/`arm64`, отдельный установщик + rc.d-сервис, покрыто CI против всех 6 поддерживаемых веб-серверов (nginx, Caddy, Traefik, HAProxy, Apache, LiteSpeed), включая сценарии proxy-chain с реальным IP — см. [FreeBSD Deployment Cookbook](cookbook/freebsd/CookBook.ru.md)
- **`arxsentinel validate`** — автономная валидация конфига с учётом топологии, используя статические манифесты плагинов; ловит сломанную разводку pipeline до деплоя
- **Pluggable queue backends** — буферизация событий исполнителей через in-memory, bbolt (файл) или Redis; выбираемо на исполнителя для bare-metal / single-host / multi-replica K8s
- **Named Channel Switch** — маршрутизация событий угроз между независимыми pipeline по имени (один детектит, другой исполняет)
- **Bot fast path** — `verify_method: ua_only` (совпадение User-Agent, без DNS) и `exempt_detectors` на бота для пропуска конкретных детекторов у доверенных краулеров
- **CLI** — `arxsentinel cleanup --cf --dry-run` для предпросмотра/очистки устаревших записей исполнителей

## Разработка плагинов

Source, Sink и Detector плагины взаимодействуют с ArxSentinel через **stdin/stdout JSON** — пишите их на любом языке. Плагин получает JSON-объект для каждой записи логов (или события) и возвращает JSON-ответ. ArxSentinel управляет жизненным циклом подпроцесса.

Полный протокол и примеры: [`docs/PLUGIN_DEV.md`](docs/PLUGIN_DEV.md).

## Whitelist

ArxSentinel предоставляет автоматическую верификацию ботов (поисковые системы)
и кастомные списки исключений (IP, CIDR, подстроки User-Agent). Занесённые в whitelist
запросы пропускают все детекторы полностью.

Подробно — смотрите [README.whitelist.ru.md](deploy/examples/README.whitelist.ru.md), примеры и настройка.

## Архитектура

```
[Source: file]  ─┐    FileSource (inotify, logrotate-aware)
[Source: stdin] ─┼──→ Merge() ──→ entries chan (*LogEntry)
[Source: http]  ─┘    (Phase 2+)
                              │
                  whitelist.Matcher ──→ custom IP/CIDR/UA? → skip
                              │
                  chaincheck.Checker ──→ Cloudflare/bogon IP? → warnings.log
                              │
                  whitelist.Verifier ──→ bot UA? → rDNS/fDNS → verified? → skip
                              │                              → fake bot? → +FakeBotScore
                  waf.RuleEngine ──→ signature match? → pass / drop / tag
                              │
                  tracker.Update(*IPState)
                    ├── TotalRequests, Requests404
                    ├── pathBuf (ring buffer, последние 64 пути)
                    └── sliding window rate counters
                              │
                  scorer.Evaluate(ipState, entry)
                    ├── decay накопленного score
                    ├── запуск 8 детекторов
                    └── вынесение вердикта (score → level)
                              │
                  [Sink: Fail2Ban file]  ──→ threats.log ──→ Fail2Ban ──→ iptables ban
                  [Sink: stdout JSON]    ──→ агрегатор логов (Loki, Splunk, Datadog)
                  [Sink: Splunk/Kafka]       (Phase 2+)
                              │
                  sentinel.log (operational)
```

Конфигурация по умолчанию (Fail2Ban file sink) полностью обратно совместима — существующие
настройки `general.log_file` и `output.threat_log` работают без изменений.

Фоновые горутины:
- **FileSource** — слежение за файлом через fsnotify, обработка mv/copytruncate logrotate
- **GC** — удаление неактивных IP каждые `gc_interval` (дефолт 60s)
- **Stats** — вывод `STATS processed/tracked/threats/suspicious` каждые `stats_interval`
- **SIGHUP listener** — конвертирует сигнал в канал для главного loop

Полная иерархия компонентов и схемы потоков данных: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

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

---

## Мультипайплайновая конфигурация

Внутри одного потока можно задать независимые pipeline — каждый со своими Sources, Detectors, Sinks и трекером IP-состояния. Используйте `tracker_group` для совместного IP-состояния между pipeline одного потока.

```yaml
streams:
  - name: nginx-monitoring
    pipelines:
      - name: api-scanner
        tracker_group: web                    # pipeline с одинаковым group делят IP-состояние
        inputs:
          - type: file
            path: /var/log/nginx/api.log
        processors:                           # плагины rule-engine, выполняются по порядку в массиве
          - plugin: waf                       # сигнатурный шлюз: отбрасывает SQLi/scanner до детекторов
            params:
              waf_config:
                rules:
                  - name: sqli_drop
                    expression: 'http.path contains "OR 1=1"'
                    action: drop
        detectors:
          probe:
            enabled: true
          rate:
            enabled: true
            threshold: 100
        outputs:
          - type: file
            path: /var/log/arxsentinel/api-threats.log
      - name: admin-watcher
        tracker_group: web                    # делит IP-состояние с api-scanner
        inputs:
          - type: file
            path: /var/log/nginx/admin.log
        detectors:
          bruteforce:
            enabled: true
          badbot:
            enabled: true
        outputs:
          - type: file
            path: /var/log/arxsentinel/admin-threats.log
```

**Правила TrackerGroup:**
- `tracker_group: web` — pipeline с одинаковым именем группы разделяют один `*state.Tracker`; атакующий, набравший очки в `api-scanner`, также отслеживается в `admin-watcher`
- `tracker_group: ""` (или отсутствует) — изолированный; в качестве ключа группы используется `name` pipeline
- Существующие конфиги (без ключа `pipelines:`) — автоматически оборачиваются в один безымянный pipeline; поведение идентично предыдущим версиям

**Prometheus-метрики** получают лейбл `pipeline` во всех векторах. Legacy-pipeline используют `pipeline=""`, поэтому существующие Grafana-дашборды работают без изменений.

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

**Warnings log** (`chain_guard.warnings_log`) — предупреждения об инфраструктурных неисправностях:

```
2026-05-20T12:34:56Z CHAIN_WARN cloudflare-ip-as-client ip=172.64.0.1 cidr=172.64.0.0/13 log=/var/log/nginx/access.log
2026-05-20T12:34:57Z CHAIN_WARN bogon-ip-as-client ip=10.0.0.1 cidr=10.0.0.0/8 log=/var/log/nginx/access.log
```

Предупреждения отличаются от угроз: `CHAIN_WARN` означает, что ArxSentinel не может надёжно
определить реальный IP атакующего. Устраните причину (смотрите [Chain Guard](#обратный-прокси-и-chain-guard))
и предупреждения прекратятся.

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

## Форматы логов

ArxSentinel поддерживает три режима форматов: **combined** (стандартный nginx), **JSON** (без перекомпиляции), и **пользовательский regex** для произвольных текстовых форматов.

Полные примеры конфигурации, маппинг полей и типичные ошибки см. в [README.log-formats.ru.md](deploy/examples/README.log-formats.ru.md).

## Обратный прокси и Chain Guard

Полное руководство по деплойму за обратным прокси (HAProxy, Traefik, Caddy, nginx), включая конфигурацию извлечения реального IP и Chain Guard (обнаружение сломанной цепочки IP).

Смотрите [`deploy/examples/reverse-proxy/README.ru.md`](deploy/examples/reverse-proxy/README.ru.md).

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


---

## Prometheus-метрики

Включить метрики в `config.yaml`, настроить scraping в Prometheus, установить bcrypt-хеш пароля и импортировать дашборд Grafana.

Полное руководство: [`deploy/grafana/README.ru.md`](deploy/grafana/README.ru.md)

---

## Дорожная карта

В активной разработке для v2.x:

- **AWS WAF executor** — обновления IP-сетов для AWS WAF rule groups
- **SSH-источник + детекторы** — парсинг auth-логов `sshd` (syslog/journald) и скоринг brute-force/credential-stuffing паттернов выделенными детекторами, с переиспользованием того же pipeline скоринга и executor'ов, что и для HTTP
- **Alert sinks** — отправка угроз в Telegram, Slack и PagerDuty с дедупликацией и rate-limiting

---

## Устранение неполадок

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

## Сторонние данные

Детектор **badbot** получает свои списки из проекта [nginx-ultimate-bad-bot-blocker](https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker), созданного **[Mitchell Krog (@mitchellkrogza)](https://github.com/mitchellkrogza)** и командой сопровождающих. Это масштабный community-проект, поддерживающий актуальные blocklists для ~685 плохих User-Agent и ~7108 нежелательных доменов-реферреров, обновляемые практически ежедневно.

Лицензия: [MIT](https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/blob/master/LICENSE.md). Списки загружаются ArxSentinel при запуске в режиме реального времени и не входят в состав дистрибутива.

Огромная благодарность Mitchell Krog и всем контрибьюторам проекта за их неустанный труд по поддержанию и обновлению этих баз данных — ваша работа делает интернет чуть безопаснее для всех.

---

[English documentation → README.md](README.md) | [Українська документація → README.uk.md](README.uk.md)
