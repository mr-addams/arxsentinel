# nginx-sentinel

Демон анализа nginx access.log в реальном времени. Отслеживает поведение IP-адресов, накапливает score через 7 детекторов и записывает подозрительные IP в threat-лог — Fail2Ban читает его и банит атакующих.

```
nginx access.log → TailReader → whitelist → tracker → scorer → threats.log → Fail2Ban → iptables
```

## Features

- **7 детекторов:** probe-сканирование, rate-аномалия, подозрительный User-Agent, bruteforce (404 ratio), sequential crawler, no-asset bot, URL overflow / WAF bypass
- **DNS-верификация ботов:** Googlebot, Bingbot, Yandex, DuckDuckGo и другие верифицируются по rDNS/fDNS — легитимные краулеры в бан не попадают
- **Whitelist:** IP, CIDR, UA-подстроки — конфигурируемые списки исключений
- **Линейный decay score:** очки затухают за `observation_window`, нет ложных банов от старого трафика
- **SIGHUP reload:** конфиг, scorer и whitelist пересоздаются без перезапуска демона
- **Graceful shutdown:** дренирование буфера строк при SIGTERM
- **Systemd + logrotate + Fail2Ban:** готовые deploy-конфиги

## Requirements

- Go 1.19+
- Linux с systemd
- Fail2Ban (опционально; без него бан не выполняется, но threat-лог ведётся)
- nginx с директивой `$real_ip` в log_format (или стандартный combined — поле `$remote_addr`)

## Quick Start

```bash
git clone https://github.com/mr-addams/nginx-sentinel
cd nginx-sentinel
sudo ./scripts/install.sh
sudo systemctl start nginx-sentinel
sudo systemctl status nginx-sentinel
```

Скрипт: собирает бинарник, создаёт пользователя `nginx-sentinel`, устанавливает systemd unit, Fail2Ban filter/jail, logrotate. Запускать от root из любой директории.

## Configuration

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

## Detectors

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

## Architecture

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

## Logs

**Operational log** (`/var/log/nginx-sentinel/sentinel.log`) — рабочий лог демона:

```
2026-04-02 14:33:10 [STARTUP] nginx-sentinel v0.1 запуск
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

## Management

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

## Troubleshooting

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
