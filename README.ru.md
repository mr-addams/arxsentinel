# nginx-sentinel

[![Release](https://img.shields.io/github/v/release/mr-addams/nginx-sentinel?include_prereleases&label=release)](https://github.com/mr-addams/nginx-sentinel/releases)
[![Build](https://github.com/mr-addams/nginx-sentinel/actions/workflows/release.yml/badge.svg)](https://github.com/mr-addams/nginx-sentinel/actions/workflows/release.yml)
[![License](https://img.shields.io/badge/license-GPL--3.0-blue)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go)](go.mod)
[![Platforms](https://img.shields.io/badge/linux-amd64%20%7C%20arm64-lightgrey?logo=linux)](https://github.com/mr-addams/nginx-sentinel/releases)
[![Packages](https://img.shields.io/badge/packages-deb%20%7C%20rpm%20%7C%20pacman-blue)](https://github.com/mr-addams/nginx-sentinel/releases)

Демон анализа nginx access.log в реальном времени. Отслеживает поведение IP-адресов, накапливает score через 7 детекторов и записывает подозрительные IP в threat-лог — Fail2Ban читает его и банит атакующих.

```
nginx access.log → TailReader → whitelist → tracker → scorer → threats.log → Fail2Ban → iptables
```

## Возможности

- **7 детекторов:** probe-сканирование, rate-аномалия, подозрительный User-Agent, bruteforce (404 ratio), sequential crawler, no-asset bot, URL overflow / WAF bypass
- **DNS-верификация ботов:** Googlebot, Bingbot, Yandex, DuckDuckGo и другие верифицируются по rDNS/fDNS — легитимные краулеры в бан не попадают
- **Whitelist:** IP, CIDR, UA-подстроки — конфигурируемые списки исключений
- **Линейный decay score:** очки затухают за `observation_window`, нет ложных банов от старого трафика
- **SIGHUP reload:** конфиг, scorer и whitelist пересоздаются без перезапуска демона
- **Graceful shutdown:** дренирование буфера строк при SIGTERM
- **Systemd + logrotate + Fail2Ban:** готовые deploy-конфиги в комплекте

## Требования

- Linux x86_64 или arm64 с systemd
- Fail2Ban
- nginx с директивой `$real_ip` в log_format (или стандартный combined — поле `$remote_addr`)

## Установка

### Debian / Ubuntu — рекомендуемый способ

Скачайте `.deb` для своей архитектуры со страницы [Releases](https://github.com/mr-addams/nginx-sentinel/releases) и установите:

```bash
# amd64
sudo apt install ./nginx-sentinel_<version>_linux_amd64.deb

# arm64
sudo apt install ./nginx-sentinel_<version>_linux_arm64.deb
```

`apt install` автоматически подтянет зависимости (`fail2ban`), установит systemd unit, Fail2Ban filter/jail, logrotate и создаст системного пользователя `nginx-sentinel`.

После установки отредактируйте конфиг и запустите сервис:

```bash
sudo nano /etc/nginx-sentinel/config.yaml
sudo systemctl enable --now nginx-sentinel
```

### Fedora / RHEL / AlmaLinux / Rocky Linux

Скачайте `.rpm` для своей архитектуры со страницы [Releases](https://github.com/mr-addams/nginx-sentinel/releases) и установите:

```bash
# amd64
sudo dnf install ./nginx-sentinel_<version>_linux_amd64.rpm

# arm64
sudo dnf install ./nginx-sentinel_<version>_linux_arm64.rpm
```

`dnf install` автоматически подтянет зависимости, установит systemd unit в `/usr/lib/systemd/system/`, Fail2Ban filter/jail, logrotate и создаст системного пользователя `nginx-sentinel`.

После установки отредактируйте конфиг и запустите сервис:

```bash
sudo nano /etc/nginx-sentinel/config.yaml
sudo systemctl enable --now nginx-sentinel
```

> **RHEL 8 / CentOS Stream 8:** используйте `dnf` или `rpm -i` напрямую. Для Fail2Ban может потребоваться репозиторий EPEL:
> `sudo dnf install epel-release && sudo dnf install fail2ban`

### Arch Linux / Manjaro

Скачайте `.pkg.tar.zst` для своей архитектуры со страницы [Releases](https://github.com/mr-addams/nginx-sentinel/releases) и установите:

```bash
# amd64
sudo pacman -U nginx-sentinel_<version>_linux_amd64.pkg.tar.zst

# arm64
sudo pacman -U nginx-sentinel_<version>_linux_arm64.pkg.tar.zst
```

Пакет установит systemd unit в `/usr/lib/systemd/system/`, конфиги Fail2Ban, logrotate и создаст системного пользователя `nginx-sentinel`.

После установки отредактируйте конфиг и запустите сервис:

```bash
sudo nano /etc/nginx-sentinel/config.yaml
sudo systemctl enable --now nginx-sentinel
```

> **Fail2Ban на Arch:** установите перед или после nginx-sentinel: `sudo pacman -S fail2ban`

### Сборка из исходников

Требуется Go 1.19+:

```bash
git clone https://github.com/mr-addams/nginx-sentinel
cd nginx-sentinel
sudo ./scripts/install.sh
sudo systemctl enable --now nginx-sentinel
```

## Конфигурация

Конфиг: `/etc/nginx-sentinel/config.yaml` (создаётся из `config.yaml` при установке).  
Переопределить путь: `NGINX_SENTINEL_CONFIG=/path/to/config.yaml`.

Ключевые параметры:

```yaml
general:
  log_file: /var/log/nginx/access.log   # nginx access.log
  stats_interval: 300s                  # период вывода STATS в operational.log

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
  threat_log: /var/log/nginx-sentinel/threats.log
  operational_log: /var/log/nginx-sentinel/sentinel.log
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

Whitelist говорит nginx-sentinel: «эти — свои, пропускай без проверки». Есть два независимых механизма: **автоматическая верификация ботов** (поисковые системы) и **кастомные исключения** (ваши IP, подсети, инструменты).

### Автоматическая верификация ботов (Googlebot, Bingbot, Яндекс и др.)

nginx-sentinel знает User-Agent строки всех крупных поисковых ботов. Когда такой бот приходит, выполняется DNS-проверка подлинности:

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

> **Для SEO-инструментов:** если ваш SEO-краулер попадает под блокировку (делает много запросов или у него подозрительный UA), добавьте его название сюда. Точную UA-строку можно посмотреть в nginx access.log:
> ```bash
> grep -i "screaming\|ahrefs\|semrush\|moz\|sitebulb" /var/log/nginx/access.log | awk -F'"' '{print $6}' | sort -u
> ```

**Достаточно подстроки** — полная строка не нужна. `"Ahrefs"` совпадёт с `"AhrefsBot/7.0"` и любой будущей версией.

---

### Применение изменений

Все изменения whitelist применяются **без перезапуска демона** — отправьте сигнал перезагрузки:

```bash
# Перезагрузить конфиг (whitelist, детекторы, пороги — всё кроме пути к лог-файлу)
systemctl kill -s HUP nginx-sentinel

# Или через PID-файл
kill -HUP $(cat /var/run/nginx-sentinel.pid)
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
nginx access.log
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

## Логи

**Operational log** (`/var/log/nginx-sentinel/sentinel.log`) — рабочий лог демона:

```
2026-04-02 14:33:10 [STARTUP] nginx-sentinel v0.2 запуск
2026-04-02 14:33:12 [THREAT] 45.134.26.8 score=85 modules=probe,rate reason="..."
2026-04-02 14:38:10 [STATS] processed=14320 tracked=87 threats=3 suspicious=12
```

Теги: `STARTUP`, `SHUTDOWN`, `CONFIG`, `THREAT`, `WHITELIST`, `STATS`, `GC`, `ERROR`, `WARN`.  
Debug-теги (`PARSER`, `TAIL`, `DETECTOR`, `SCORER`) видны только при `logging.debug: true`.

**Threat log** (`/var/log/nginx-sentinel/threats.log`) — читает Fail2Ban:

```
2026-04-02T14:33:12Z THREAT 45.134.26.8 score=85 modules=probe,rate reason="probe:/.env,rate:142rps"
2026-04-02T14:35:01Z WARN   92.63.104.12 score=55 modules=useragent reason="ua:Nuclei/3.1.0"
```

Fail2Ban failregex: `THREAT <HOST> score=\d+` (файл `deploy/fail2ban/filter.d/nginx-sentinel.conf`).

## Управление

```bash
# Статус и логи
systemctl status nginx-sentinel
journalctl -u nginx-sentinel -f

# Перезагрузка конфига без перезапуска (SIGHUP)
kill -HUP $(cat /var/run/nginx-sentinel.pid)
# или
systemctl kill -s HUP nginx-sentinel

# Остановка (graceful — дренирует буфер строк)
systemctl stop nginx-sentinel

# Ручной бан/разбан через Fail2Ban
fail2ban-client status nginx-sentinel
fail2ban-client set nginx-sentinel unbanip 1.2.3.4
```

**Что обновляется при SIGHUP:** scorer (детекторы + пороги), whitelist matcher, debug/color флаги, пути к лог-файлам.  
**Что НЕ обновляется:** tracker (state IP), DNS cache, TailReader (путь к access.log требует перезапуска).

## Деплой за обратным прокси

> **Внимание:** если nginx стоит за прокси и `$real_ip` настроен некорректно,
> nginx-sentinel будет выставлять score **IP-адресу прокси**, а не реальному атакующему.
> Fail2Ban заблокирует ваш же прокси — сайт упадёт для всех.

### Как это работает

```
[Клиент 1.2.3.4] → [Прокси] → (X-Forwarded-For / X-Real-IP заголовок) → [nginx]
                                                                               ↓
                                               переменная $real_ip в log_format
                                                                               ↓
                                                                  nginx-sentinel
```

Модуль `ngx_http_realip_module` читает заголовок с проброшенным IP и подставляет
его как `$real_ip` — именно эту переменную nginx-sentinel использует для всей детекции.

### Готовые конфиги

Полные рабочие примеры для каждого прокси находятся в `deploy/examples/reverse-proxy/`:

| Прокси | Файлы |
|--------|-------|
| **HAProxy** | [`haproxy/haproxy.cfg`](deploy/examples/reverse-proxy/haproxy/haproxy.cfg), [`nginx.conf`](deploy/examples/reverse-proxy/haproxy/nginx.conf) |
| **Traefik** | [`traefik/traefik.yml`](deploy/examples/reverse-proxy/traefik/traefik.yml), [`nginx.conf`](deploy/examples/reverse-proxy/traefik/nginx.conf) |
| **Caddy** | [`caddy/Caddyfile`](deploy/examples/reverse-proxy/caddy/Caddyfile), [`nginx.conf`](deploy/examples/reverse-proxy/caddy/nginx.conf) |
| **nginx как RP** | [`nginx-rp/nginx-upstream.conf`](deploy/examples/reverse-proxy/nginx-rp/nginx-upstream.conf), [`nginx-origin.conf`](deploy/examples/reverse-proxy/nginx-rp/nginx-origin.conf) |

Каждый пример содержит конфиг прокси и конфиг origin-nginx с `set_real_ip_from`,
`real_ip_header` и форматом лога `combined_realip`.

### Минимальный конфиг nginx (для любого прокси)

```nginx
http {
    set_real_ip_from  <ip-или-cidr-прокси>;  # доверяем только своему прокси
    real_ip_header    X-Real-IP;             # или X-Forwarded-For для Traefik
    real_ip_recursive off;                   # on для цепочек X-Forwarded-For

    log_format combined_realip
        '$remote_addr - $remote_user [$time_local] '
        '"$request" $status $body_bytes_sent '
        '"$http_referer" "$http_user_agent" "$real_ip"';

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
3. Перезагрузите без рестарта: `kill -HUP $(pgrep nginx-sentinel)` — или `systemctl kill -s HUP nginx-sentinel`.

Пути **дополняют** (а не заменяют) встроенный список sensitive-путей по умолчанию.
Чтобы использовать только свой список, задайте в `detectors.probe.paths:` ровно те пути, которые нужны.

---

## Решение проблем

**Демон не запускается — ошибка threat log:**  
Проверьте права на `/var/log/nginx-sentinel/` — директория должна принадлежать пользователю `nginx-sentinel`.

**Fail2Ban не банит — проверьте формат лога:**  
```bash
fail2ban-regex /var/log/nginx-sentinel/threats.log /etc/fail2ban/filter.d/nginx-sentinel.conf
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

[English documentation → README.md](README.md)
