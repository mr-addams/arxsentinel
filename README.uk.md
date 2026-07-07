# ArxSentinel

[![Release](https://img.shields.io/github/v/release/mr-addams/arxsentinel?include_prereleases&label=release)](https://github.com/mr-addams/arxsentinel/releases)
[![Build](https://github.com/mr-addams/arxsentinel/actions/workflows/release.yml/badge.svg)](https://github.com/mr-addams/arxsentinel/actions/workflows/release.yml)
[![License](https://img.shields.io/badge/license-Elastic--2.0-blue)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go)](go.mod)
[![Platforms](https://img.shields.io/badge/linux-amd64%20%7C%20arm64%20%7C%20arm%2Fv7%20%7C%20riscv64%20%7C%20i386-lightgrey?logo=linux)](https://github.com/mr-addams/arxsentinel/releases)
[![FreeBSD](https://img.shields.io/badge/freebsd-386%20%7C%20amd64%20%7C%20arm%20%7C%20arm64-red?logo=freebsd)](https://github.com/mr-addams/arxsentinel/releases)
[![Packages](https://img.shields.io/badge/packages-deb%20%7C%20rpm%20%7C%20pacman-blue)](https://github.com/mr-addams/arxsentinel/releases)

> 🌐 [English](README.md) | [Русская документация](README.ru.md) | 📖 [Книга рецептів конфігурацій](cookbook/CookBook.uk.md)

**Розподілений конвеєр обробки подій безпеки для будь-якого HTTP-сервера** — від одного nginx VPS до флоту вузлів.  
~12 МБ RAM · єдиний бінарник · без залежностей у runtime · розширюється через exec+JSON-плагіни на будь-якій мові.  
Збирайте події на одній машині, скоруйте на іншій, баньте на третій — через вбудовану шифровану мережу вузлів (QUIC · TLS 1.3 · Ed25519 · TOFU). Без Redis, без Kafka, без VPN. → [Посібник з розподіленої обробки](docs/DISTRIBUTED.uk.md)

> **Ліцензія:** ArxSentinel поширюється за [Elastic License 2.0](LICENSE). Безкоштовне використання для власної інфраструктури. Комерційне використання як керованого сервісу безпеки або телеметрії, або як частини керованого сервісу, вимагає окремої угоди. Деталі — у файлі [LICENSE](LICENSE).

> **Побудований на [arx-core](https://github.com/mr-addams/arx-core).** Рушій конвеєра ArxSentinel,
> система плагінів (Source/Sink/Detector/Processor/Executor) та міст NCS працюють на базі
> [arx-core](https://github.com/mr-addams/arx-core/blob/v0.1.0/README.md) — універсального потоково-орієнтованого
> фреймворку телеметрії. Життєвий цикл рушія, runtime-контракт та базові інтерфейси плагінів
> живуть у [`arx-core/docs/`](https://github.com/mr-addams/arx-core/tree/v0.1.0/docs)
> (`architecture.md`, `contract.md`, `plugin-development.md`). Цей README описує
> продуктовий шар ArxSentinel: детектори безпеки, скоринг загроз, розводку NCS та
> Cloudflare/MikroTik/OpenWrt/OPNsense/nginx-екзекутори. Див. [Архітектура](docs/ARCHITECTURE.md) для розділення.

```
  ╔══════════════════════════════════════════════════════════════════╗
  ║  SOURCES                                                         ║
  ║  nginx · Apache · Caddy · Traefik · HAProxy · LiteSpeed          ║
  ║  file │ stdin │ syslog │ http (push/pull · Firehose/Loki/OTLP)   ║
  ║  exec+JSON plugin (будь-яка мова)                                ║
  ╚═══════════════════════════╤══════════════════════════════════════╝
                              │ розібрані записи логу
  ╔═══════════════════════════╧══════════════════════════════════════╗
  ║  PROCESSORS                                                      ║
  ║                                                                  ║
  ║  Whitelist ── власні IP/CIDR/UA · DNS-верифікація ботів          ║
  ║  ChainGuard ─ перевірка цілісності ланцюжка IP за проксі         ║
  ║  WAF rule-engine (processors: · pass / drop / tag)               ║
  ║                                                                  ║
  ║  Детектори (вбудовані)    Детектори (плагіни)                    ║
  ║  ├─ probe      score 25  └─ exec+JSON detector (будь-яка мова)   ║
  ║  ├─ bruteforce score 30                                          ║
  ║  ├─ crawler    score 20                                          ║
  ║  ├─ noasset    score 20                                          ║
  ║  ├─ rate       score 25                                          ║
  ║  ├─ useragent  score 40/20/15                                    ║
  ║  ├─ overflow   score 30                                          ║
  ║  └─ badbot     score 60                                          ║
  ║                                                                  ║
  ║  Scorer ── накопичує score → WARN (≥50) │ THREAT (≥80)           ║
  ╚═══════════════════════════╤══════════════════════════════════════╝
                              │ події загроз
  ╔═══════════════════════════╧══════════════════════════════════════╗
  ║  SINKS  (пасивне логування)                                      ║
  ║  file (формат fail2ban) · stdout JSON · exec+JSON plugin         ║
  ║  Grafana Loki · Splunk HEC · Datadog Logs API  (форвардинг у SIEM)║
  ╚═══════════════════════════╤══════════════════════════════════════╝
                              │ sentinel-threat sink → AttachWriter()
  ╔═══════════════════════════╧══════════════════════════════════════╗
  ║  NAMED CHANNEL SWITCH  (черга Point-to-Point)                    ║
  ║  memory │ bbolt (file) │ redis │ transport (QUIC-мережа вузлів)  ║
  ╚═══════════════════════════╤══════════════════════════════════════╝
                              │ ncs://<channel-name> → AttachReader()
  ╔═══════════════════════════╧═══════════════════════════════════════════════════════════════════════╗
  ║  EXECUTORS  (активна відповідь — опціонально)                                                     ║
  ║  Cloudflare IP Lists · MikroTik address-list · nginx blocklist · OpenWrt ipset · OPNsense alias   ║
  ╚═══════════════════════════════════════════════════════════════════════════════════════════════════╝
```

## Сценарії використання

ArxSentinel масштабується від класичного VPS до розподіленого Kubernetes-кластера — кожен сценарій нижче — готова стартова точка.

### 1. Класичний захист вебу — nginx + Fail2Ban

Один конфіг, профіль не потрібен. Працює з коробки:

```yaml
general:
  log_file: /var/log/nginx/access.log
output:
  threat_log: /var/log/arxsentinel/threats.log
```

### 2. Docker Compose sidecar

Монтуйте обсяг nginx-логів; ArxSentinel читає його як sidecar. Див. [`deploy/examples/docker/`](deploy/examples/docker/):

```yaml
# docker-compose.yml — витяг
services:
  arxsentinel:
    image: ghcr.io/mr-addams/arxsentinel:latest
    volumes:
      - nginx_logs:/var/log/nginx:ro
    environment:
      ARXSENTINEL_LOG_FILE: /var/log/nginx/access.log
```

### 3. Kubernetes DaemonSet

По одному pod на вузол, читає хост-логи через `hostPath`. Див. [`deploy/examples/kubernetes/`](deploy/examples/kubernetes/) та [README Helm-чарту](deploy/container/k8s/arxsentinel/README.md):

```bash
helm install arxsentinel ./deploy/container/k8s/arxsentinel \
  --set logVolume.hostPath=/var/log/nginx
```

### 4. Агрегація з кількох серверів

Спостерігайте за кількома серверами в одному процесі — повна ізоляція IP-стану для кожного потоку:

```yaml
streams:
  - name: frontend
    log_file: /var/log/nginx/access.log
  - name: api
    log_file: /var/log/apache2/api.log
    profile: apache
```

Коли логи живуть на *різних машинах* — не монтуйте й не пересилайте їх:
запустіть 12-мегабайтний колектор поруч із кожним логом і прокидайте події
через вбудовану шифровану мережу (див. [сценарій 8](#8-розподілений-конвеєр--збирай-будь-де-детектуй-централізовано-бань-на-межі)).

### 5. Користувацький формат логу

API-шлюз, власний лог додатку, довільний текстовий формат — надайте regex із именованими групами:

```yaml
parser:
  log_format: "custom"
  custom_regex: '(?P<ip>\S+) \S+ \S+ \[.*?\] "\S+ (?P<path>\S+) \S+" (?P<status>\d+) (?P<size>\d+) "(?P<ua>[^"]*)"'
```

### 6. Зовнішній детектор-плагін — exec+JSON

Будь-який скрипт або бінарник як додатковий детектор; викликається на запит через stdin/stdout на будь-якій мові. Див. [Розробка плагінів](#розробка-плагінів):

```yaml
detectors:
  plugins:
    - name: ml-classifier
      exec: /opt/plugins/classify.py
      score: 45
```

### 7. Користувацький вихідний sink — exec+JSON

Маршрутизуйте загрози до будь-якої мети — SIEM, webhook, Telegram, власний скрипт:

```yaml
sinks:
  - type: exec
    exec: /opt/plugins/send-to-siem.sh
```

### 8. Observability — форвардинг у Loki / Splunk / Datadog

Надсилайте скорані події загроз напряму у вашу log-платформу як sink
першого класу — зручно, коли у вас вже є SIEM і ArxSentinel потрібен як
фід поруч (або замість) Fail2Ban/executor-респондерів. JSON-конверт
рекомендується для читабельності в log-платформі:

```yaml
sinks:
  - type: loki
    format: json
    loki_url: https://loki.example.com:3100
    loki_labels:
      job: arxsentinel
```

Та сама форма працює для `type: splunk` (HEC JSON-ендпоінт — потрібні
`splunk_url` + `splunk_token`) та `type: datadog` (Logs API v2 — потрібен
`datadog_url` з регіоном, наприклад `https://http-intake.logs.datadoghq.com`,
плюс `datadog_api_key`). TLS, mTLS, батчинг, gzip і поля мульти-tenantності
доступні per sink — див. [docs/providers/observability/](docs/providers/observability/).
Quick-start рецепти: [cookbook/observability/](cookbook/observability/).

### 9. Розподілений конвеєр — збирай будь-де, детектуй централізовано, бань на межі

Той самий бінарник стає **колектором**, **детектором** чи **респондером**
лише через конфіг, з'єднуючись вбудованою взаємно автентифікованою
QUIC-мережею — без брокера повідомлень, без log shipper'а, без VPN:

```
  Pi / VPS / NAS колектори           машина детекції              enforcement
 ┌────────────┐
 │ логи nginx  │──┐   "edge-raw"   ┌───────────────┐  "scored"  ┌───────────────────────────────────────┐
 └────────────┘  ├──────────────▶│ 8 детекторів · │──────────▶│ MikroTik · OpenWrt · OPNsense · nginx │
 ┌────────────┐  │  QUIC/TLS 1.3  │ WAF · скоринг  │            │ CF WAF · SIEM                         │
 │ логи API    │──┘   Ed25519+TOFU └───────────────┘            └───────────────────────────────────────┘
 └────────────┘
```

```yaml
# вузол-колектор — лише парсинг, прокид без скорингу (12 МБ, працює на Pi)
streams:
  - pipelines:
      - raw_forward: true
        inputs:  [{type: file, path: /var/log/nginx/access.log}]
        outputs: [{type: sentinel-threat, name: edge-raw, format: raw-line,
                   queue: {type: transport, mode: send, peer: "brain:4097"}}]
```

Атакувальник, що промацує кілька ваших сервісів, накопичує **один сумарний
score** на вузлі-детекторі — і отримує бан всюди одночасно. Повний посібник
оператора з 5 готовими топологіями (хоумлаб → корпоративний потік у SIEM):
**[docs/DISTRIBUTED.uk.md](docs/DISTRIBUTED.uk.md)** · рецепти:
[cookbook/distributed-ncs/](cookbook/distributed-ncs/README.md) — кожна
топологія перевірена CI на справжніх контейнерах.

---

## Швидкий старт

Встановлює пакет, додає systemd-сервіс та одразу працює з nginx:

```bash
curl -fsSL https://raw.githubusercontent.com/mr-addams/arxsentinel/main/scripts/get.sh | sudo bash
```

Відредагуйте конфіг під ваш сервер, потім перезавантажте без перезапуску:

```bash
sudo nano /etc/arxsentinel/config.yaml
sudo systemctl kill -s HUP arxsentinel
```

Для Docker, Kubernetes та інших способів встановлення — див. [Встановлення](#встановлення) далі.

---

## Встановлення

### Швидке встановлення — будь-який дистрибутив (рекомендовано)

Скрипт автоматично визначає дистрибутив та архітектуру, завантажує потрібний пакет з GitHub Releases,
встановлює його через штатний менеджер пакетів, додає до автозапуску та запускає сервіс:

```bash
curl -fsSL https://raw.githubusercontent.com/mr-addams/arxsentinel/main/scripts/get.sh | sudo bash
```

Працює на Debian, Ubuntu, Fedora, RHEL, AlmaLinux, Rocky Linux та Arch Linux.
Потребує `curl` та `sudo`. Fail2Ban встановлюється автоматично, якщо відсутній.

Сервіс запускається одразу і працює з nginx з коробки — профіль не потрібен. Щоб перемкнутися на інший сервер (apache, caddy, traefik, haproxy-http, litespeed або довільний regex):

```bash
sudo nano /etc/arxsentinel/config.yaml
sudo systemctl kill -s HUP arxsentinel   # перезавантаження без перезапуску
```

---

### Debian / Ubuntu — ручне встановлення пакета

Завантажте `.deb` для своєї архітектури зі сторінки [Releases](https://github.com/mr-addams/arxsentinel/releases) та встановіть:

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

`apt install` автоматично підтягне залежності (`fail2ban`), встановить systemd unit, Fail2Ban filter/jail, logrotate та створить системного користувача `arxsentinel`.

Після встановлення відредагуйте конфіг та запустіть сервіс:

```bash
sudo nano /etc/arxsentinel/config.yaml
sudo systemctl enable --now arxsentinel
```

### Fedora / RHEL / AlmaLinux / Rocky Linux

Завантажте `.rpm` для своєї архітектури зі сторінки [Releases](https://github.com/mr-addams/arxsentinel/releases) та встановіть:

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

`dnf install` автоматично підтягне залежності, встановить systemd unit у `/usr/lib/systemd/system/`, Fail2Ban filter/jail, logrotate та створить системного користувача `arxsentinel`.

Після встановлення відредагуйте конфіг та запустіть сервіс:

```bash
sudo nano /etc/arxsentinel/config.yaml
sudo systemctl enable --now arxsentinel
```

> **RHEL 8 / CentOS Stream 8:** використовуйте `dnf` або `rpm -i` напряму. Для Fail2Ban може знадобитися репозиторій EPEL:
> `sudo dnf install epel-release && sudo dnf install fail2ban`

### Arch Linux / Manjaro

Завантажте `.pkg.tar.zst` для своєї архітектури зі сторінки [Releases](https://github.com/mr-addams/arxsentinel/releases) та встановіть:

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

Пакет встановить systemd unit у `/usr/lib/systemd/system/`, конфіги Fail2Ban, logrotate та створить системного користувача `arxsentinel`.

Після встановлення відредагуйте конфіг та запустіть сервіс:

```bash
sudo nano /etc/arxsentinel/config.yaml
sudo systemctl enable --now arxsentinel
```

> **Fail2Ban на Arch:** встановіть перед або після arxsentinel: `sudo pacman -S fail2ban`

### FreeBSD

Скрипт `get.sh` вище не підходить (він розрахований лише на Linux-дистрибутиви з `/etc/os-release`). Завантажте архів `freebsd_<arch>` зі сторінки [Releases](https://github.com/mr-addams/arxsentinel/releases) і запустіть інсталятор з архіву:

```sh
fetch https://github.com/mr-addams/arxsentinel/releases/latest/download/arxsentinel_<version>_freebsd_<arch>.tar.gz
tar xzf arxsentinel_<version>_freebsd_<arch>.tar.gz
cd arxsentinel_<version>_freebsd_<arch>
sudo sh install.sh
```

`install.sh` створює системного користувача `arxsentinel`, встановлює бінарник і rc.d-сервіс, засіває конфіг із вбудованого прикладу (при повторному запуску наявний конфіг не перезаписується). Увімкнути та запустити:

```sh
sysrc arxsentinel_enable=YES
service arxsentinel start
```

Повний посібник — структура шляхів на FreeBSD, керування rc.d-сервісом та запуск веб-сервера в `podman` на FreeBSD (драйвер сховища, налаштування firewall, особливості контейнерної мережі): [FreeBSD Deployment Cookbook](cookbook/freebsd/CookBook.uk.md).

### Збірка з вихідного коду

Потрібен Go 1.26+:

```bash
git clone https://github.com/mr-addams/arxsentinel
cd arxsentinel
sudo ./scripts/install.sh
sudo systemctl enable --now arxsentinel
```

### Docker

Дистроблес-образ (~12 МБ), запускається від користувача з uid 65532, надає метрики Prometheus на `:9117`.

```bash
docker run -d \
  -v /var/log/nginx/access.log:/var/log/nginx/access.log:ro \
  -v /var/log/arxsentinel:/var/log/arxsentinel \
  -p 127.0.0.1:9117:9117 \
  ghcr.io/mr-addams/arxsentinel:latest
```

Детальніше: [README.docker.md](deploy/container/docker/README.md) — Docker Compose, монтування томів, змінні середовища, інтеграція з Fail2Ban.

### Kubernetes (Helm)

Топологія DaemonSet — один pod на вузол, читає access.log через `hostPath`.

```bash
helm install arxsentinel ./deploy/container/k8s/arxsentinel \
  --set logVolume.hostPath=/var/log/nginx \
  --set threatLog.hostPath=/var/log/arxsentinel
```

Детальніше: [Helm README](deploy/container/k8s/arxsentinel/README.md) — опис values, Prometheus Operator, деплой у хмару.

## Підтримувані HTTP-сервери

### Таблиця сумісності

| Сервер | Профіль | Необхідне налаштування |
|--------|---------|------------------------|
| nginx | *(за замовчуванням — профіль не потрібен)* | Нема — nginx combined log format працює з коробки |
| Apache | `apache` | Нема — стандартний CLF |
| Traefik | `traefik` | Додайте `fields.headers.names.User-Agent/Referer: keep` до accessLog — див. [`deploy/examples/traefik/`](deploy/examples/traefik/) |
| LiteSpeed / OpenLiteSpeed | `litespeed` | Нема — стандартний CLF |
| Caddy | `caddy` | [xcaddy](https://github.com/caddyserver/xcaddy) + плагін [transform-encoder](https://github.com/caddyserver/transform-encoder) — див. [`deploy/examples/caddy/`](deploy/examples/caddy/) |
| HAProxy | `haproxy-http` | `http-request capture` + користувацький `log-format` з UA — див. [`deploy/examples/haproxy/`](deploy/examples/haproxy/) |

> У кожному релізі публікується таблиця **Tested product versions** з точними версіями серверів, на яких валідувалась збірка — див. [GitHub Releases](https://github.com/mr-addams/arxsentinel/releases).

> **nginx:** налаштування `profile:` не потрібне. Стандартний CombinedParser обробляє nginx combined log format з коробки. Вкажіть лише `general.log_file` зі шляхом до вашого access.log.

Вбудовані профілі — налаштування regex та маппінгу полів не потрібне. Вкажіть `parser.profile` з іменем сервера для Apache, Traefik, Caddy, HAProxy, LiteSpeed або OpenLiteSpeed:

**Приклад — Apache:**

```yaml
parser:
  profile: "apache"

general:
  log_file: /var/log/apache2/access.log

output:
  threat_log: /var/log/arxsentinel/threats.log
```

Готові конфіги для кожного сервера знаходяться в [`deploy/examples/`](deploy/examples/):

```
deploy/examples/
├── apache/      httpd.conf + sentinel-config.yaml
├── caddy/       Caddyfile + sentinel-config.yaml
├── traefik/     traefik.yml + sentinel-config.yaml
├── haproxy/     haproxy.cfg + sentinel-config.yaml
└── litespeed/   httpd_config.conf + sentinel-config.yaml
```

> **Примітка — LiteSpeed / OpenLiteSpeed:** Обидва сервери (LSWS та OLS) за замовчуванням пишуть Apache CLF —
> налаштування формату лога не потрібне. Шлях логу: `/usr/local/lsws/logs/access.log`
> (глобально) або `/usr/local/lsws/logs/<vhostname>/access.log` (за віртуальним хостом).
> За зворотним проксі: увімкніть "Use Client IP in Header" у WebAdmin, щоб `%h` логував
> справжній IP клієнта. Див. `deploy/examples/litespeed/` для повного конфігу.

> **Примітка — Caddy:** Вбудований JSON-енкодер Caddy v2 виводить вкладені об'єкти. Профіль `caddy` потребує плагіна
> [caddy-transform-encoder](https://github.com/caddyserver/transform-encoder)
> для виводу у форматі CLF. Див. `deploy/examples/caddy/Caddyfile` для налаштування.

## Можливості

- **8 детекторів:** probe-сканування, rate-аномалія, підозрілий User-Agent, bruteforce (404 ratio), sequential crawler, no-asset bot, URL overflow / WAF bypass, community bad-bot blocklist
- **Chain Guard:** виявляє IP-адреси Cloudflare/CDN і bogon/RFC 1918/CGNAT у позиції client IP — сигналізує про неправильно налаштований ланцюжок проксі до того, як детектори ArxSentinel втратять здатність визначати справжніх зловмисників
- **DNS-верифікація ботів:** Googlebot, Bingbot, Yandex, DuckDuckGo та інші верифікуються через rDNS/fDNS — легітимні краулери не потрапляють у бан
- **Multi-stream + Multi-pipeline:** декілька лог-файлів в одному процесі; всередині кожного потоку — незалежні pipeline з власними детекторами, джерелами, sink'ами та трекером IP-стану (або спільний трекер через `tracker_group`)
- **Observability-sink'и:** прокидайте події загроз у Grafana Loki, Splunk HEC або Datadog Logs API — форвардинг у SIEM як альтернатива (або доповнення) до респондерів Fail2Ban/executor
- **Розподілений конвеєр (Distributed NCS):** розтягніть pipeline на кілька машин через вбудовану шифровану мережу вузлів (QUIC · TLS 1.3 · Ed25519-ідентичність · TOFU-пінінг) — прокидайте сирі розпарсені записи на центральний детектор або скоровані вердикти на віддалені респондери; без брокера, без log shipper'а, без VPN. Див. [docs/DISTRIBUTED.uk.md](docs/DISTRIBUTED.uk.md)
- **Whitelist:** IP, CIDR, UA-підрядки — конфігуровані списки винятків
- **Лінійний decay score:** очки затухають за `observation_window`, немає хибних банів від старого трафіку
- **Prometheus-метрики:** `/metrics` на налаштовуваному порту (за замовчуванням `:9117`), опційна basic auth з bcrypt; дашборд Grafana в комплекті
- **Health endpoint:** `/health` завжди повертає `200 {"status":"ok"}` без авторизації — готовий для Docker `HEALTHCHECK`, k8s probes та балансувальників
- **JSON-формат логів:** перемикання на JSON-парсинг через `parser.log_format: "json"` без перекомпіляції
- **SIGHUP reload:** конфіг, scorer, парсер і whitelist перестворюються без перезапуску демона
- **Graceful shutdown:** дренування буфера рядків при SIGTERM
- **Systemd + logrotate + Fail2Ban:** готові deploy-конфіги в комплекті

## Вимоги

- Linux amd64 / arm64 / arm/v7 / riscv64 / i386 з systemd, **або** FreeBSD 386 / amd64 / arm / arm64 з rc.d
- Fail2Ban
- HTTP-сервер, що пише access.log у підтримуваному форматі (nginx, Apache, Caddy, Traefik, HAProxy, LiteSpeed, OpenLiteSpeed — або довільний regex)

## Конфігурація

Конфіг: `/etc/arxsentinel/config.yaml` (створюється з `config.yaml` при встановленні).  
Перевизначити шлях: `ARXSENTINEL_CONFIG=/path/to/config.yaml`.

Ключові параметри:

```yaml
general:
  log_file: /var/log/nginx/access.log   # лог-файл для спостереження (приклад nginx; див. також: streams:)
  stats_interval: 300s                  # період виводу STATS в operational.log

parser:
  # profile: "apache"  # вкажіть для не-nginx серверів: apache | caddy | traefik | haproxy-http | litespeed
  #                     # nginx combined log format працює без налаштування профілю

scoring:
  alert_threshold: 50    # score → WARN у threat-лог
  ban_threshold: 80      # score → THREAT + Fail2Ban бан
  observation_window: 300s  # вікно накопичення/decay score

detectors:
  probe:
    enabled: true
    score: 25
    paths: [/.env, /.git/config, /wp-config.php, ...]  # список probe-шляхів

  rate:
    enabled: true
    threshold: 100   # запитів за window
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
    ratio_threshold: 0.6  # >60% відповідей 404
    score: 30

  crawler:
    enabled: true
    min_sequential: 5  # /page/1, /page/2, ... N підряд
    score: 20

  noasset:
    enabled: true
    min_page_requests: 3
    asset_ratio_threshold: 0.1  # <10% запитів до статики
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
    check_referrer: false   # opt-in: також перевіряти заголовок Referer (~7108 паттернів)

blocklist:
  storage: ""              # "" = лише в пам'яті; шлях до файлу = bbolt (зберігається між запусками)
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
  fake_bot_score: 35      # штраф за імітацію Googlebot/Bingbot
  dns_verify_timeout: 2s  # таймаут DNS-верифікації бота в pipeline
  custom:
    ips: [127.0.0.1]
    cidrs: [10.0.0.0/8]
    ua_substrings: [internal-monitor]

output:
  threat_log: /var/log/arxsentinel/threats.log
  operational_log: /var/log/arxsentinel/sentinel.log
```

> **Обмеження yaml.v3:** якщо в config.yaml вказана секція (наприклад, `scoring:`), вона повинна містити **всі** поля — інакше невказані обнуляться. Відсутні секції повністю беруть Go-дефолти.

## Детектори

| Детектор | Тригер | Дефолтний score |
|----------|--------|-----------------|
| **probe** | запит до .env, .git, wp-config.php та ін. | 25 за запит |
| **rate** | >100 запитів за 60s | 25 |
| **useragent** | сканер/грабер/автоматизація/порожній UA | 15–40 |
| **bruteforce** | >60% відповідей 404 при ≥10 запитах | 30 |
| **crawler** | ≥5 послідовних числових URL (/page/1..N) | 20 |
| **noasset** | <10% запитів до статики при ≥3 сторінках | 20 |
| **overflow** | URL >2048 символів або WAF bypass keywords | 30 |
| **badbot** | UA (або Referer) збігається з community-blocklist (~685 паттернів) | 60 |

Score накопичується з лінійним decay за `observation_window`. При досягненні `alert_threshold` — запис WARN, при `ban_threshold` — THREAT + Fail2Ban.

## Процесор-плагіни

Процесори запускаються до ланцюжка детекторів. Вони можуть коротко замкнути pipeline (пропустити), повністю відкинути подію або позначити її для подальшого скорингу.

| Плагін | Опис |
|--------|------|
| `whitelist` | IP/CIDR/path/UA allowlist — коротко замикає pipeline |
| `chaincheck` | Перевіряє цілісність ланцюжка IP за зворотним проксі |
| `waf` | Правило-рушій — pass / drop / tag з інтеграцією в scorer |

## Розгортання

### systemd — bare metal

Охоплено встановниками пакетів вище. Використовуйте `systemctl` для управління сервісом та `kill -HUP` для живого перезавантаження. Повна довідка команд — див. [Керування](#керування).

### FreeBSD — rc.d

Охоплено FreeBSD-інсталятором вище. Використовуйте `service arxsentinel <start|stop|status>` для управління сервісом; `sysrc arxsentinel_enable=YES` вмикає автозапуск після перезавантаження. Повний посібник, включно із запуском веб-сервера в `podman` на FreeBSD: [FreeBSD Deployment Cookbook](cookbook/freebsd/CookBook.uk.md).

### Docker Compose

ArxSentinel працює як sidecar поряд з HTTP-сервером, читаючи спільні обсяги логів.
Готовий Compose-файл та конфіг: [`deploy/examples/docker/`](deploy/examples/docker/).
Повний Docker-гайд: [README.docker.md](deploy/container/docker/README.md).

### Kubernetes

DaemonSet (один pod на вузол, читає хост-логи) або sidecar (читає з emptyDir, спільної з контейнером додатку).
Готові маніфести: [`deploy/examples/kubernetes/`](deploy/examples/kubernetes/).
Helm-чарт з довідкою values: [Helm README](deploy/container/k8s/arxsentinel/README.md).

## Виконавці

Виконавці — це плагіни зі станом, що виконуються після оцінки загроз. На відміну від Sink (пасивний запис у лог), виконавці активно керують зовнішніми ресурсами: ведуть локальний dedup-словник, застосовують TTL-закінчення та збирають статистику.

> **Примітка про термінологію:** «Executor» / «Виконавець» — термін рівня плагіна/конфігу (`executors:` у YAML, `pkg/executorplugins/*` у коді) — використовується у всьому README та коді. У топології [Distributed NCS](docs/DISTRIBUTED.uk.md) вузол, що запускає виконавці, називається **Responder** (у парі з **Collector** і **Detector** — три ролі вузлів). Це ті самі плагіни, просто інша термінологія для опису *де* вони виконуються у multi-node розгортанні.

| Виконавець | Пакет | Опис |
|---|---|---|
| **cloudflare** | `pkg/executor/cloudflare` | Додає IP-загрози до Cloudflare IP List; автоматично видаляє застарілі записи через TTL sweep |
| **nginx** | `pkg/executor/nginx` | Записує заблоковані IP до простого файлу блокування (TTL автовиходу, атомарні записи, опційна команда перезавантаження); ви включаєте файл до nginx як вам зручно |
| **mikrotik** | `pkg/executor/mikrotik` | Керує list адрес файервола RouterOS v7 через REST API; TTL-автороззабиття, видаляє лише записи, створені arxsentinel, сумісний з CHR/ARM |
| **openwrt** | `pkg/executor/openwrt` | Керує nftables ipset через ubus-ендпоінт роутера (uhttpd-mod-ubus) за допомогою стандартних rpcd-об'єктів `uci`/`rc`; пакетна правка UCI + один reload за цикл, TTL рахує сам плагін (не native nftables) |
| **opnsense** | `pkg/executor/opnsense` | Керує аліасом файервола через REST API OPNsense (`alias_util` add/delete/list); незалежний point add/delete на подію (без пакетування — API застосовує зміни негайно), TTL рахує сам плагін через активний sweep |

Детальніше: [docs/executors.md](docs/executors.md) — огляд фреймворку та додавання власних виконавців.
Детальніше: [docs/executor-cloudflare.md](docs/executor-cloudflare.md) — конфігурація та усунення несправностей Cloudflare.
Детальніше: [docs/executor-nginx.md](docs/executor-nginx.md) — виконавець nginx blocklist.

## Нещодавно доставлені функції

- **Підтримка FreeBSD** — нативні збірки `386`/`amd64`/`arm`/`arm64`, окремий інсталятор + rc.d-сервіс, покрито CI проти всіх 6 підтримуваних веб-серверів (nginx, Caddy, Traefik, HAProxy, Apache, LiteSpeed), включно зі сценаріями proxy-chain з реальним IP — див. [FreeBSD Deployment Cookbook](cookbook/freebsd/CookBook.uk.md)
- **`arxsentinel validate`** — автономна валідація конфігу з урахуванням топології, використовуючи статичні маніфести плагінів; ловить зламану розводку pipeline до деплою
- **Pluggable queue backends** — буферизація подій виконавців через in-memory, bbolt (файл) або Redis; вибір на виконавця для bare-metal / single-host / multi-replica K8s
- **Named Channel Switch** — маршрутизація подій загроз між незалежними pipeline за іменем (один детектує, інший виконує)
- **Bot fast path** — `verify_method: ua_only` (збіг User-Agent, без DNS) та `exempt_detectors` на бота для пропускання конкретних детекторів у довірених краулерів
- **CLI** — `arxsentinel cleanup --cf --dry-run` для попереднього перегляду/очищення застарілих записів виконавців

## Розробка плагінів

Source, Sink та Detector плагіни спілкуються з ArxSentinel через **stdin/stdout JSON** — пишіть їх на будь-якій мові. Плагін отримує JSON-об'єкт на запис (або подію) і повертає JSON-відповідь. ArxSentinel управляє жизненним циклом subprocessu.

Повна специфікація протоколу та приклади: [`docs/PLUGIN_DEV.md`](docs/PLUGIN_DEV.md).

## Whitelist

ArxSentinel надає автоматичну верифікацію ботів (пошукові системи)
та кастомні списки винятків (IP, CIDR, підрядки User-Agent). Занесені до whitelist
запити пропускають усі детектори повністю.

Детально — див. [README.whitelist.uk.md](deploy/examples/README.whitelist.uk.md), приклади та налаштування.

## Архітектура

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
                    ├── pathBuf (ring buffer, останні 64 шляхи)
                    └── sliding window rate counters
                              │
                  scorer.Evaluate(ipState, entry)
                    ├── decay накопиченого score
                    ├── запуск 8 детекторів
                    └── винесення вердикту (score → level)
                              │
                  [Sink: Fail2Ban file]  ──→ threats.log ──→ Fail2Ban ──→ iptables ban
                  [Sink: stdout JSON]    ──→ агрегатор логів (Loki, Splunk, Datadog)
                  [Sink: Splunk/Kafka]       (Phase 2+)
                              │
                  sentinel.log (operational)
```

Конфігурація за замовчуванням (Fail2Ban file sink) повністю зворотньо сумісна — існуючі
налаштування `general.log_file` та `output.threat_log` працюють без змін.

Фонові горутини:
- **FileSource** — спостереження за файлом через fsnotify, обробка mv/copytruncate logrotate
- **GC** — видалення неактивних IP кожні `gc_interval` (дефолт 60s)
- **Stats** — вивід `STATS processed/tracked/threats/suspicious` кожні `stats_interval`
- **SIGHUP listener** — конвертує сигнал у канал для головного loop

Повна ієрархія компонентів та схеми потоків даних: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Моніторинг кількох потоків

Запустіть один процес ArxSentinel, який спостерігає за кількома лог-файлами одночасно — один конвеєр на домен, повна ізоляція.

### Конфігурація

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

> **Важливо:** `streams:` і `general.log_file` взаємно виключають одне одного. Використовуйте одне або інше.

Кожен потік має власний трекер, scorer, whitelist і лог загроз. Повільна атака або збій в одному потоці не впливає на інші.

### Зворотна сумісність

Класична конфігурація з `general.log_file` продовжує працювати — вона автоматично конвертується в один безіменний потік (мітка `stream=""` у Prometheus). Міграція конфігу не потрібна.

---

## Мультипайплайнова конфігурація

Всередину одного потоку можна задати незалежні pipeline — кожен зі своїми Sources, Detectors, Sinks та трекером IP-стану. Використовуйте `tracker_group` для спільного IP-стану між pipeline одного потоку.

```yaml
streams:
  - name: nginx-monitoring
    pipelines:
      - name: api-scanner
        tracker_group: web                    # pipeline з однаковим group діляться IP-станом
        inputs:
          - type: file
            path: /var/log/nginx/api.log
        processors:                           # плагіни rule-engine, виконуються за порядком у масиві
          - plugin: waf                       # сигнатурний шлюз: відкидає SQLi/scanner до детекторів
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
        tracker_group: web                    # ділить IP-стан з api-scanner
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
- `tracker_group: web` — pipeline з однаковим іменем групи діляться одним `*state.Tracker`; зловмисник, що набрав очки в `api-scanner`, також відстежується в `admin-watcher`
- `tracker_group: ""` (або відсутній) — ізольований; як ключ групи використовується `name` pipeline
- Наявні конфіги (без ключа `pipelines:`) — автоматично обгортаються в один безіменний pipeline; поведінка ідентична попереднім версіям

**Prometheus-метрики** отримують мітку `pipeline` у всіх векторах. Legacy-pipeline використовують `pipeline=""`, тому наявні Grafana-дашборди працюють без змін.

### Fail2Ban при кількох потоках

Кожен потік записує у свій `threat_log`. Створіть окрему пастку Fail2Ban для кожного файлу:

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

Дашборд включає змінну **Stream** для фільтрації панелей за потоком. Імпортуйте `deploy/grafana/arxsentinel-dashboard.json` (v2).

---

## Логи

**Operational log** (`/var/log/arxsentinel/sentinel.log`) — робочий лог демона:

```
2026-04-02 14:33:10 [STARTUP] arxsentinel v1.0.0 started
2026-04-02 14:33:12 [THREAT] 45.134.26.8 score=85 modules=probe,rate reason="..."
2026-04-02 14:38:10 [STATS] processed=14320 tracked=87 threats=3 suspicious=12
```

Теги: `STARTUP`, `SHUTDOWN`, `CONFIG`, `THREAT`, `WHITELIST`, `STATS`, `GC`, `ERROR`, `WARN`.  
Debug-теги (`PARSER`, `TAIL`, `DETECTOR`, `SCORER`) видні лише при `logging.debug: true`.

**Threat log** (`/var/log/arxsentinel/threats.log`) — читає Fail2Ban:

```
2026-04-02T14:33:12Z THREAT 45.134.26.8 score=85 modules=probe,rate reason="probe:/.env,rate:142rps"
2026-04-02T14:35:01Z WARN   92.63.104.12 score=55 modules=useragent reason="ua:Nuclei/3.1.0"
```

Fail2Ban failregex: `THREAT <HOST> score=\d+` (файл `deploy/fail2ban/filter.d/arxsentinel.conf`).

**Warnings log** (`chain_guard.warnings_log`) — попередження про інфраструктурні несправності:

```
2026-05-20T12:34:56Z CHAIN_WARN cloudflare-ip-as-client ip=172.64.0.1 cidr=172.64.0.0/13 log=/var/log/nginx/access.log
2026-05-20T12:34:57Z CHAIN_WARN bogon-ip-as-client ip=10.0.0.1 cidr=10.0.0.0/8 log=/var/log/nginx/access.log
```

Попередження відрізняються від загроз: `CHAIN_WARN` означає, що ArxSentinel не може надійно
визначити справжній IP зловмисника. Усуньте причину та попередження припиняться.

## Керування

```bash
# Статус та логи
systemctl status arxsentinel
journalctl -u arxsentinel -f

# Перезавантаження конфігу без перезапуску (SIGHUP)
kill -HUP $(cat /var/run/arxsentinel.pid)
# або
systemctl kill -s HUP arxsentinel

# Зупинка (graceful — дренує буфер рядків)
systemctl stop arxsentinel

# Ручний бан/розбан через Fail2Ban
fail2ban-client status arxsentinel
fail2ban-client set arxsentinel unbanip 1.2.3.4
```

**Що оновлюється при SIGHUP:** scorer (детектори + пороги), whitelist matcher, debug/color прапори, шляхи до лог-файлів.  
**Що НЕ оновлюється:** tracker (state IP), DNS cache, FileSource (шлях до access.log потребує перезапуску).

## Формати логів

ArxSentinel підтримує три режими форматів: **combined** (стандартний nginx), **JSON** (без перекомпіляції), та **користувацький regex** для довільних текстових форматів.

Повні приклади конфігурації, маппінг полів та типові помилки див. у [README.log-formats.uk.md](deploy/examples/README.log-formats.uk.md).

## Зворотний проксі та Chain Guard

Повне керівництво по деплойму за зворотним проксі (HAProxy, Traefik, Caddy, nginx), включаючи конфігурацію вилучення справжнього IP та Chain Guard (виявлення зламаного ланцюжка IP).

Див. [`deploy/examples/reverse-proxy/README.uk.md`](deploy/examples/reverse-proxy/README.uk.md).

## Конфігурації для CMS

Готові перевизначення `probe.paths` для найпопулярніших PHP-стеків знаходяться в
`deploy/examples/cms/`. Скопіюйте потрібні шляхи у свій `config.yaml`:

| Файл | Для кого |
|------|----------|
| [`wordpress.yaml`](deploy/examples/cms/wordpress.yaml) | WordPress — `wp-login.php`, `xmlrpc.php`, перерахування користувачів через REST |
| [`laravel.yaml`](deploy/examples/cms/laravel.yaml) | Laravel — `.env`, `/storage/`, `/vendor/`, Telescope, Horizon |
| [`drupal.yaml`](deploy/examples/cms/drupal.yaml) | Drupal — `/user/login`, `settings.php`, `update.php` |
| [`joomla.yaml`](deploy/examples/cms/joomla.yaml) | Joomla — `/administrator/`, `configuration.php` |
| [`generic-php.yaml`](deploy/examples/cms/generic-php.yaml) | Custom PHP — phpinfo, phpMyAdmin, Adminer, резервні копії |

**Як застосувати конфіг CMS:**

1. Відкрийте `deploy/examples/cms/<cms>.yaml` і скопіюйте список `paths:`.
2. Вставте його в `config.yaml` під `detectors.probe.paths:`.
3. Перезавантажте без перезапуску: `kill -HUP $(pgrep arxsentinel)` — або `systemctl kill -s HUP arxsentinel`.

Шляхи **доповнюють** (а не замінюють) вбудований список sensitive-шляхів за замовчуванням.
Щоб використовувати лише свій список, задайте в `detectors.probe.paths:` рівно ті шляхи, які потрібні.


---

## Prometheus-метрики

Увімкнути метрики в `config.yaml`, налаштувати scraping у Prometheus, встановити bcrypt-хеш пароля та імпортувати дашборд Grafana.

Повне керівництво: [`deploy/grafana/README.uk.md`](deploy/grafana/README.uk.md)

---

## Дорожна карта

В активній розробці для v2.x:

- **Alert sinks** — надсилання загроз до Telegram, Slack та PagerDuty з дедуплікацією та rate-limiting
- **AWS WAF executor** — оновлення IP-наборів для AWS WAF rule-груп
- **SSH-джерело + детектори** — парсинг auth-логів `sshd` (syslog/journald) і скоринг brute-force/credential-stuffing патернів виділеними детекторами, з перевикористанням того самого pipeline скорингу та executor'ів, що й для HTTP

---

## Вирішення проблем

**Демон не запускається — помилка threat log:**  
Перевірте права на `/var/log/arxsentinel/` — директорія повинна належати користувачу `arxsentinel`.

**Fail2Ban не банить — перевірте формат лога:**  
```bash
fail2ban-regex /var/log/arxsentinel/threats.log /etc/fail2ban/filter.d/arxsentinel.conf
```

**Забагато хибних WARN — знизьте чутливість:**  
Зменшіть `score` або підвищте пороги (`threshold`, `ratio_threshold`) у конфізі, потім `kill -HUP`.

**Налагодження pipeline — увімкніть debug-режим:**  
```yaml
logging:
  debug: true
```
Перезапустіть або `kill -HUP`. В operational.log з'являться рядки `[PARSER]`, `[DETECTOR]`, `[SCORER]` на кожен запит.

**Високе споживання пам'яті:**  
Зменшіть `state.max_tracked_ips` (дефолт 100000; кожен IP ≈ 2.5 KB → 100k ≈ 250 MB).

---

## Сторонні дані

Детектор **badbot** отримує свої списки з проекту [nginx-ultimate-bad-bot-blocker](https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker), створеного **[Mitchell Krog (@mitchellkrogza)](https://github.com/mitchellkrogza)** та команди супроводжувачів. Це масштабний community-проект, що підтримує актуальні blocklists для ~685 поганих User-Agent та ~7108 небажаних доменів-реферерів, які оновлюються практично щодня.

Ліцензія: [MIT](https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/blob/master/LICENSE.md). Списки завантажуються ArxSentinel при запуску в режимі реального часу та не входять до складу дистрибутиву.

Величезна вдячність Mitchell Krog та всім контриб'юторам проекту за їхню невтомну працю з підтримки та оновлення цих баз даних — ваша робота робить інтернет трохи безпечнішим для всіх.

---

[Документація англійською → README.md](README.md) | [Документація російською → README.ru.md](README.ru.md)
