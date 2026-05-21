# ArxSentinel

[![Release](https://img.shields.io/github/v/release/mr-addams/arxsentinel?include_prereleases&label=release)](https://github.com/mr-addams/arxsentinel/releases)
[![Build](https://github.com/mr-addams/arxsentinel/actions/workflows/release.yml/badge.svg)](https://github.com/mr-addams/arxsentinel/actions/workflows/release.yml)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go)](go.mod)
[![Platforms](https://img.shields.io/badge/linux-amd64%20%7C%20arm64-lightgrey?logo=linux)](https://github.com/mr-addams/arxsentinel/releases)
[![Packages](https://img.shields.io/badge/packages-deb%20%7C%20rpm%20%7C%20pacman-blue)](https://github.com/mr-addams/arxsentinel/releases)

Пильний страж вашого вебсервера: читає HTTP access-логи в реальному часі, оцінює кожен IP через 8 поведінкових детекторів і блокує зловмисників через Fail2Ban. Працює з nginx, Apache, Caddy, Traefik, HAProxy, LiteSpeed та OpenLiteSpeed.

Підтримує **nginx, Apache, Caddy, Traefik, HAProxy, LiteSpeed та OpenLiteSpeed** через вбудовані профілі. nginx працює з коробки без налаштування профілю. Caddy та HAProxy потребують мінімального одноразового налаштування. Довільні формати логів — через regex. Декілька лог-файлів в одному процесі.

```
access.log → TailReader → whitelist → tracker → scorer → threats.log → Fail2Ban → iptables
```

## Підтримувані HTTP-сервери

### Таблиця сумісності

| Сервер | Профіль | Необхідне налаштування |
|--------|---------|------------------------|
| nginx | *(за замовчуванням — профіль не потрібен)* | Нема — nginx combined log format працює з коробки |
| Apache | `apache` | Нема — стандартний CLF |
| Traefik | `traefik` | Нема — стандартний access log (CLF) |
| Caddy | `caddy` | [xcaddy](https://github.com/caddyserver/xcaddy) + плагін [transform-encoder](https://github.com/caddyserver/transform-encoder) |
| HAProxy | `haproxy-http` | `option httplog` у haproxy.cfg + rsyslog для запису у файл |
| LiteSpeed / OpenLiteSpeed | `litespeed` | Нема — стандартний CLF |

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

> **Примітка — HAProxy:** HAProxy включає мілісекунди у мітку часу
> (`14:30:00.123`). ArxSentinel парсить цей формат через запасний шаблон
> `haproxyTimeLayout` — всі детектори, включно з rate, отримують коректну мітку часу.

> **Примітка — Caddy:** Вбудований JSON-енкодер Caddy v2 виводить вкладені об'єкти.
> Профіль `caddy` потребує плагіна
> [caddy-transform-encoder](https://github.com/caddyserver/transform-encoder)
> для виводу у форматі CLF. Дивіться `deploy/examples/caddy/Caddyfile` для налаштування.

> **Примітка — LiteSpeed / OpenLiteSpeed:** Обидва сервери (LSWS та OLS) за замовчуванням пишуть Apache CLF —
> налаштування формату лога не потрібне. Якщо sentinel стоїть за проксі, увімкніть «Use Client IP in Header»
> у WebAdmin («Server Configuration → Use Client IP in Header»), щоб реальний IP клієнта писався
> до `%h` безпосередньо. Дивіться `deploy/examples/litespeed/` для повного конфігу.

## Можливості

- **8 детекторів:** probe-сканування, rate-аномалія, підозрілий User-Agent, bruteforce (404 ratio), sequential crawler, no-asset bot, URL overflow / WAF bypass, community bad-bot blocklist
- **Chain Guard:** виявляє IP-адреси Cloudflare/CDN і bogon/RFC 1918/CGNAT у позиції client IP — сигналізує про неправильно налаштований ланцюжок проксі до того, як детектори ArxSentinel втратять здатність визначати справжніх зловмисників
- **DNS-верифікація ботів:** Googlebot, Bingbot, Yandex, DuckDuckGo та інші верифікуються через rDNS/fDNS — легітимні краулери не потрапляють у бан
- **Multi-stream:** декілька лог-файлів в одному процесі — повна ізоляція конвеєра на потік
- **Whitelist:** IP, CIDR, UA-підрядки — конфігуровані списки винятків
- **Лінійний decay score:** очки затухають за `observation_window`, немає хибних банів від старого трафіку
- **Prometheus-метрики:** `/metrics` на налаштовуваному порту (за замовчуванням `:9117`), опційна basic auth з bcrypt; дашборд Grafana в комплекті
- **Health endpoint:** `/health` завжди повертає `200 {"status":"ok"}` без авторизації — готовий для Docker `HEALTHCHECK`, k8s probes та балансувальників
- **JSON-формат логів:** перемикання на JSON-парсинг через `parser.log_format: "json"` без перекомпіляції
- **SIGHUP reload:** конфіг, scorer, парсер і whitelist перестворюються без перезапуску демона
- **Graceful shutdown:** дренування буфера рядків при SIGTERM
- **Systemd + logrotate + Fail2Ban:** готові deploy-конфіги в комплекті

## Вимоги

- Linux x86_64 або arm64 з systemd
- Fail2Ban
- HTTP-сервер, що пише access.log у підтримуваному форматі (nginx, Apache, Caddy, Traefik, HAProxy, LiteSpeed, OpenLiteSpeed — або довільний regex)

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
```

Пакет встановить systemd unit у `/usr/lib/systemd/system/`, конфіги Fail2Ban, logrotate та створить системного користувача `arxsentinel`.

Після встановлення відредагуйте конфіг та запустіть сервіс:

```bash
sudo nano /etc/arxsentinel/config.yaml
sudo systemctl enable --now arxsentinel
```

> **Fail2Ban на Arch:** встановіть перед або після arxsentinel: `sudo pacman -S fail2ban`

### Збірка з вихідного коду

Потрібен Go 1.19+:

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

Детальніше: [README.docker.md](README.docker.md) — Docker Compose, монтування томів, змінні середовища, інтеграція з Fail2Ban.

### Kubernetes (Helm)

Топологія DaemonSet — один pod на вузол, читає access.log через `hostPath`.

```bash
helm install arxsentinel ./deploy/container/k8s/arxsentinel \
  --set logVolume.hostPath=/var/log/nginx \
  --set threatLog.hostPath=/var/log/arxsentinel
```

Детальніше: [README.helm.md](README.helm.md) — опис values, Prometheus Operator, деплой у хмару.

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
| **badbot** | UA (або Referer) збігається з community-blocklist (~685 паттернів). Дані: [nginx-ultimate-bad-bot-blocker](https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker) | 60 |

Score накопичується з лінійним decay за `observation_window`. При досягненні `alert_threshold` — запис WARN, при `ban_threshold` — THREAT + Fail2Ban.

## Whitelist

ArxSentinel пропонує автоматичну верифікацію ботів (пошукові системи)
та кастомні списки винятків (IP, CIDR, підрядки User-Agent). Занесені до whitelist
запити пропускають усі детектори повністю.

Детально — див. [README.whitelist.uk.md](README.whitelist.uk.md), приклади та налаштування.

## Архітектура

```
access.log (nginx / apache / caddy / traefik / haproxy / litespeed)
       │
  TailReader (inotify, logrotate-aware)
       │
  lines chan (буфер LinesBufSize)
       │
  whitelist.Matcher ──→ custom IP/CIDR/UA? → skip
       │
  chaincheck.Checker ──→ Cloudflare/bogon IP? → warnings.log (CHAIN_WARN)
       │
  whitelist.Verifier ──→ bot UA? → rDNS/fDNS → verified? → skip
       │                                      → fake bot? → +FakeBotScore
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
  output.ThreatLogger ──→ threats.log ──→ Fail2Ban ──→ iptables ban
                      └──→ sentinel.log (operational)
```

Фонові горутини:
- **TailReader** — спостереження за файлом через fsnotify, обробка mv/copytruncate logrotate
- **GC** — видалення неактивних IP кожні `gc_interval` (дефолт 60s)
- **Stats** — вивід `STATS processed/tracked/threats/suspicious` кожні `stats_interval`
- **SIGHUP listener** — конвертує сигнал у канал для головного loop

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
визначити справжній IP зловмисника. Усуньте причину (див. [Chain Guard](#chain-guard----виявлення-зламаного-ланцюжка-ip))
і попередження припиняться.

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
**Що НЕ оновлюється:** tracker (state IP), DNS cache, TailReader (шлях до access.log потребує перезапуску).

## Формати логів

ArxSentinel підтримує три режими форматів: **combined** (стандартний nginx), **JSON** (без перекомпіляції), та **користувацький regex** для довільних текстових форматів.

Повні приклади конфігурації, маппінг полів та типові помилки див. у [README.log-formats.uk.md](README.log-formats.uk.md).

## Зворотний проксі та Chain Guard

Повне керівництво по деплойю за зворотним проксі (HAProxy, Traefik, Caddy, nginx), включаючи конфігурацію вилучення справжнього IP та Chain Guard (виявлення зламаного ланцюжка IP).

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

Детектор **badbot** отримує свої списки з проекту [nginx-ultimate-bad-bot-blocker](https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker), створеного **[Mitchell Krog (@mitchellkrogza)](https://github.com/mitchellkrogza)** та командою супроводжувачів. Це масштабний community-проект, що підтримує актуальні blocklists для ~685 поганих User-Agent та ~7108 небажаних доменів-реферерів, які оновлюються практично щодня.

Ліцензія: [MIT](https://github.com/mitchellkrogza/nginx-ultimate-bad-bot-blocker/blob/master/LICENSE.md). Списки завантажуються ArxSentinel при запуску в режимі реального часу та не входять до складу дистрибутиву.

Величезна вдячність Mitchell Krog та всім контриб'юторам проекту за їхню невтомну працю з підтримки та оновлення цих баз даних — ваша робота робить інтернет трохи безпечнішим для всіх.

---

[English documentation → README.md](README.md) | [Документація російською → README.ru.md](README.ru.md)
