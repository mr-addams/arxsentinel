# ArxSentinel — Посібник розгортання Helm-чарта

Helm-чарт ArxSentinel розгортає DaemonSet, який запускає по одному pod-у на кожному вузлі,
читає лог доступу вузла через `hostPath` та записує події загроз у налаштовану директорію хоста
для інтеграції з Fail2Ban.

## Передумови

- Helm 3.x
- Kubernetes 1.24+
- Docker-образ доступний з кластера (`ghcr.io/mr-addams/arxsentinel`)

## Швидкий старт

```bash
# Спостерігати за /var/log/nginx на кожному вузлі, тільки метрики (без Fail2Ban)
helm install arxsentinel ./deploy/container/k8s/arxsentinel \
  --set logVolume.hostPath=/var/log/nginx
```

## Повне розгортання — bare-metal / k3s з Fail2Ban

```bash
# Створити директорію логів загроз на кожному вузлі:
# (запустити на кожному вузлі, або використовувати init container у DaemonSet)
sudo mkdir -p /var/log/arxsentinel
sudo chown 65532:65532 /var/log/arxsentinel

helm install arxsentinel ./deploy/container/k8s/arxsentinel \
  --set logVolume.hostPath=/var/log/nginx \
  --set threatLog.hostPath=/var/log/arxsentinel
```

## Довідник Values

| Ключ | Тип | Дефолт | Опис |
|---|---|---|---|
| `image.repository` | string | `ghcr.io/mr-addams/arxsentinel` | Репозиторій образу |
| `image.tag` | string | `""` | Тег образу; за замовчуванням `Chart.AppVersion` |
| `image.pullPolicy` | string | `IfNotPresent` | Політика витягування образу |
| `logVolume.hostPath` | string | `/var/log/nginx` | Шлях хоста, що містить лог доступу |
| `logFile` | string | `access.log` | Ім'я файла логу доступу всередину `logVolume.hostPath` |
| `threatLog.hostPath` | string | `""` | Шлях хоста для логу загроз; порожньо = без монтування hostPath |
| `metrics.enabled` | bool | `true` | Увімкнути endpoint Prometheus `/metrics` |
| `metrics.port` | int | `9117` | Порт метрик |
| `service.type` | string | `ClusterIP` | Тип Kubernetes Service |
| `serviceMonitor.enabled` | bool | `false` | Створити ServiceMonitor для Prometheus Operator |
| `serviceMonitor.namespace` | string | `monitoring` | Простір імен Prometheus Operator |
| `serviceMonitor.interval` | string | `30s` | Інтервал скрейпінгу |
| `resources.limits.cpu` | string | `200m` | Ліміт CPU |
| `resources.limits.memory` | string | `128Mi` | Ліміт пам'яті |
| `resources.requests.cpu` | string | `20m` | Запит CPU |
| `resources.requests.memory` | string | `32Mi` | Запит пам'яті |
| `tolerations` | list | `[]` | Tolerations для вузлів |
| `nodeSelector` | object | `{}` | Селектор вузлів |
| `env` | object | див. values.yaml | Перевизначення змінних `ARXSENTINEL_*` |
| `extraEnv` | list | `[]` | Додаткові змінні оточення (довільні пари ключ/значення) |

## Інтеграція з Fail2Ban (bare-metal / k3s)

Встановіть `threatLog.hostPath` у директорію, присутню на кожному вузлі.
Fail2Ban на хості читає `threats.log` з цієї директорії:

```bash
helm upgrade arxsentinel ./deploy/container/k8s/arxsentinel \
  --set threatLog.hostPath=/var/log/arxsentinel
```

Налаштуйте Fail2Ban на хості:

```ini
# /etc/fail2ban/jail.d/arxsentinel.conf
[arxsentinel]
enabled  = true
filter   = arxsentinel
logpath  = /var/log/arxsentinel/threats.log
maxretry = 1
bantime  = 3600
```

Конфіги filter та jail: [`deploy/fail2ban/`](deploy/fail2ban/).

## Інтеграція з Prometheus Operator (ServiceMonitor)

```bash
helm upgrade arxsentinel ./deploy/container/k8s/arxsentinel \
  --set serviceMonitor.enabled=true \
  --set serviceMonitor.namespace=monitoring \
  --set serviceMonitor.additionalLabels.release=prometheus
```

`ServiceMonitor` націлює на порт `metrics` (9117) на ClusterIP-сервісі ArxSentinel.

## Спостереження за control-plane вузлами

За замовчуванням pod-и DaemonSet не планують на control-plane вузлах. Додайте toleration:

```bash
helm upgrade arxsentinel ./deploy/container/k8s/arxsentinel \
  --set "tolerations[0].key=node-role.kubernetes.io/control-plane" \
  --set "tolerations[0].operator=Exists" \
  --set "tolerations[0].effect=NoSchedule"
```

## Перевизначення конфігурації через змінні оточення

Значення `env` безпосередньо відображаються на змінні оточення `ARXSENTINEL_*`.
Вони мають пріоритет над ConfigMap-ом, відрендереним у `config.yaml`:

```yaml
# values-production.yaml
env:
  ARXSENTINEL_SCORING_BAN_THRESHOLD: "60"
  ARXSENTINEL_SCORING_OBSERVATION_WINDOW: "600s"
  ARXSENTINEL_METRICS_USERNAME: "prometheus"
  ARXSENTINEL_METRICS_PASSWORD_HASH: "$2y$10$..."
```

```bash
helm upgrade arxsentinel ./deploy/container/k8s/arxsentinel -f values-production.yaml
```

> **Примітка:** Поля-масиви (шляхи зондів, конфіги ботів, додаткові шаблони) неможливо встановити через змінні оточення.
> Перевизначте їх, відредагувавши ConfigMap або змонтувавши окремий файл конфігурації.

### Повний довідник змінних оточення

> Повні приклади з усіма YAML-only секціями: [`config.reference.yaml`](../../../cookbook/config.reference.yaml) у корені репозиторія.

Масиви позначені **YAML-only** — налаштовуйте через ConfigMap `config.yaml` або змонтований файл конфігурації.

#### General, логування, парсер

| Змінна | Тип | Дефолт | Опис |
|---|---|---|---|
| `ARXSENTINEL_GENERAL_LOG_FILE` | string | `/var/log/nginx/access.log` | Шлях логу доступу |
| `ARXSENTINEL_GENERAL_PID_FILE` | string | `/tmp/arxsentinel.pid` | Шлях PID-файла |
| `ARXSENTINEL_GENERAL_LINES_BUF_SIZE` | int | `1000` | Розмір буфера каналу |
| `ARXSENTINEL_GENERAL_TAIL_RETRY_INTERVAL` | duration | `5s` | Інтервал retry для tail |
| `ARXSENTINEL_GENERAL_STATS_INTERVAL` | duration | `300s` | Інтервал логу статистики |
| `ARXSENTINEL_LOGGING_DEBUG` | bool | `false` | Увімкнути debug-теги логування |
| `ARXSENTINEL_LOGGING_CONSOLE_COLOR` | bool | `false` | ANSI-розфарбування у консолі |
| `ARXSENTINEL_PARSER_PROFILE` | string | `` | Профіль сервера (apache, caddy, traefik, haproxy-http) |
| `ARXSENTINEL_PARSER_LOG_FORMAT` | string | `combined` | Формат логу (combined, json, regex) |
| `ARXSENTINEL_PARSER_REGEX_PATTERN` | string | `` | Go regex (обов'язковий для regex-формату) |
| `ARXSENTINEL_PARSER_TIMEZONE` | string | `UTC` | Часовий пояс (зарезервовано) |
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
| `ARXSENTINEL_SCORING_DECAY` | string | `linear` | Алгоритм затухання (YAML-only) |
| `ARXSENTINEL_STATE_GC_INTERVAL` | duration | `60s` | Інтервал збирання сміття |
| `ARXSENTINEL_STATE_MAX_TRACKED_IPS` | int | `100000` | Макс. відстежуваних IP |

#### Джерело (syslog)

| Змінна | Тип | Дефолт | Опис |
|---|---|---|---|
| `ARXSENTINEL_SYSLOG_MAX_CONNECTIONS` | int | `1000` | Макс. одночасних TCP-з'єднань syslog (H5) |

#### Детектори — probe, bruteforce, crawler, no-asset

| Змінна | Тип | Дефолт | Опис |
|---|---|---|---|
| `ARXSENTINEL_DETECTORS_PROBE_ENABLED` | bool | `true` | Увімкнути сканер зондів |
| `ARXSENTINEL_DETECTORS_PROBE_SCORE` | int | `25` | Бали за влучення на шлях зонду |
| `ARXSENTINEL_DETECTORS_PROBE_PATHS` | array | _(29 шляхів)_ | **YAML-only** |
| `ARXSENTINEL_DETECTORS_BRUTEFORCE_ENABLED` | bool | `true` | Увімкнути bruteforce за ratio 404 |
| `ARXSENTINEL_DETECTORS_BRUTEFORCE_MIN_REQUESTS` | int | `10` | Мін. запитів перед перевіркою |
| `ARXSENTINEL_DETECTORS_BRUTEFORCE_RATIO_THRESHOLD` | float | `0.6` | Поріг ratio 404 |
| `ARXSENTINEL_DETECTORS_BRUTEFORCE_SCORE` | int | `30` | Бали за bruteforce |
| `ARXSENTINEL_DETECTORS_CRAWLER_ENABLED` | bool | `true` | Увімкнути послідовний crawler |
| `ARXSENTINEL_DETECTORS_CRAWLER_MIN_SEQUENTIAL` | int | `5` | Мін. послідовні запити |
| `ARXSENTINEL_DETECTORS_CRAWLER_SCORE` | int | `20` | Бали за crawler |
| `ARXSENTINEL_DETECTORS_NOASSET_ENABLED` | bool | `true` | Увімкнути детектор ботів без активів |
| `ARXSENTINEL_DETECTORS_NOASSET_MIN_PAGE_REQUESTS` | int | `3` | Мін. запитів сторінок |
| `ARXSENTINEL_DETECTORS_NOASSET_ASSET_RATIO_THRESHOLD` | float | `0.1` | Поріг ratio активів |
| `ARXSENTINEL_DETECTORS_NOASSET_SCORE` | int | `20` | Бали за no-asset |
| `ARXSENTINEL_DETECTORS_NOASSET_ASSET_EXTENSIONS` | array | _(12 розширень)_ | **YAML-only** |

#### Детектори — rate, user-agent, overflow, badbot

| Змінна | Тип | Дефолт | Опис |
|---|---|---|---|
| `ARXSENTINEL_DETECTORS_RATE_ENABLED` | bool | `true` | Увімкнути аномалію rate |
| `ARXSENTINEL_DETECTORS_RATE_WINDOW` | duration | `60s` | Вікно підрахунку rate |
| `ARXSENTINEL_DETECTORS_RATE_THRESHOLD` | int | `100` | Запитів у вікні |
| `ARXSENTINEL_DETECTORS_RATE_SCORE` | int | `25` | Бали за rate |
| `ARXSENTINEL_DETECTORS_USERAGENT_ENABLED` | bool | `true` | Увімкнути аномалію UA |
| `ARXSENTINEL_DETECTORS_USERAGENT_SCANNER_SCORE` | int | `40` | Бали за scanner UA |
| `ARXSENTINEL_DETECTORS_USERAGENT_GRABBER_SCORE` | int | `20` | Бали за grabber UA |
| `ARXSENTINEL_DETECTORS_USERAGENT_AUTOMATION_SCORE` | int | `15` | Бали за automation tool UA |
| `ARXSENTINEL_DETECTORS_USERAGENT_EMPTY_UA_SCORE` | int | `30` | Бали за порожній UA |
| `ARXSENTINEL_DETECTORS_USERAGENT_EXTRA_SCANNER_PATTERNS` | array | `[]` | **YAML-only** |
| `ARXSENTINEL_DETECTORS_USERAGENT_EXTRA_GRABBER_PATTERNS` | array | `[]` | **YAML-only** |
| `ARXSENTINEL_DETECTORS_USERAGENT_EXTRA_AUTOMATION_PATTERNS` | array | `[]` | **YAML-only** |
| `ARXSENTINEL_DETECTORS_OVERFLOW_ENABLED` | bool | `true` | Увімкнути overflow/WAF bypass |
| `ARXSENTINEL_DETECTORS_OVERFLOW_MAX_URL_LENGTH` | int | `2048` | Поріг довжини URL |
| `ARXSENTINEL_DETECTORS_OVERFLOW_SCORE` | int | `30` | Бали за overflow |
| `ARXSENTINEL_DETECTORS_OVERFLOW_SUSPICIOUS_PARAMS` | array | _(7 параметрів)_ | **YAML-only** |
| `ARXSENTINEL_DETECTORS_BADBOT_ENABLED` | bool | `true` | Увімкнути community blocklist |
| `ARXSENTINEL_DETECTORS_BADBOT_SCORE` | int | `60` | Бали за збіг у blocklist |
| `ARXSENTINEL_DETECTORS_BADBOT_CHECK_UA` | bool | `true` | Перевірити UA проти badbot-ua |
| `ARXSENTINEL_DETECTORS_BADBOT_CHECK_REFERRER` | bool | `false` | Перевірити Referer проти badbot-ref |

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
| `ARXSENTINEL_WHITELIST_BOTS` | array | _(11 ботів)_ | **YAML-only** |
| `ARXSENTINEL_CHAIN_GUARD_ENABLED` | bool | `false` | Увімкнути перевірку цілісності ланцюга проксі |
| `ARXSENTINEL_CHAIN_GUARD_WARNINGS_LOG` | string | `` | Шлях логу попереджень |
| `ARXSENTINEL_CHAIN_GUARD_CLOUDFLARE_ENABLED` | bool | `true` | Увімкнути перевірку діапазонів IP Cloudflare |
| `ARXSENTINEL_CHAIN_GUARD_CLOUDFLARE_REFRESH_INTERVAL` | duration | `24h` | Інтервал оновлення списку IP Cloudflare |
| `ARXSENTINEL_CHAIN_GUARD_BOGON_ENABLED` | bool | `true` | Увімкнути перевірку bogon/RFC1918/CGNAT |
| `ARXSENTINEL_BLOCKLIST_STORAGE` | string | `` | Шлях кешу blocklist на диск |
| `ARXSENTINEL_OUTPUT_THREAT_LOG` | string | `/var/log/arxsentinel/threats.log` | Шлях логу загроз |
| `ARXSENTINEL_OUTPUT_OPERATIONAL_LOG` | string | `/var/log/arxsentinel/sentinel.log` | Шлях операційного логу |
| `ARXSENTINEL_METRICS_ENABLED` | bool | `false` | Увімкнути endpoint Prometheus |
| `ARXSENTINEL_METRICS_LISTEN_ADDR` | string | `:9117` | Адреса прослуховування метрик |
| `ARXSENTINEL_METRICS_USERNAME` | string | `` | Користувач Basic auth |
| `ARXSENTINEL_METRICS_PASSWORD_HASH` | string | `` | bcrypt-хеш пароля |
| `ARXSENTINEL_PIPELINE_BUFFER_SIZE` | int | `8192` | Глибина буфера каналу (збільшити при сплесках трафіку) |
| `ARXSENTINEL_PIPELINE_SHUTDOWN_TIMEOUT` | duration | `15s` | Вікно graceful shutdown |

### Basic auth для метрик

Коли налаштований basic auth для метрик, поле `ARXSENTINEL_METRICS_PASSWORD_HASH`
повинне містити **bcrypt-хеш** (не простий пароль). Створіть його за допомогою:

```bash
htpasswd -bnBC 10 "" your-password | tr -d ':\n'
```

Приклад values.yaml:

```yaml
env:
  ARXSENTINEL_METRICS_USERNAME: "prometheus"
  ARXSENTINEL_METRICS_PASSWORD_HASH: "$2y$10$..."
```

> **Попередження:** У Helm values, знаки `$` у bcrypt-хешу повинні бути екрановані
> або обгорнуті в одинарні лапки, щоб запобігти інтерпретації їх як Helm-templating.
> Використовуйте `$2y$10$...` безпосередньо у `values.yaml` — Helm коректно обробляє raw `$` у простих змінних оточення.
> Якщо виникають помилки рендеринга, перевірте, що хеш не містить символів, які інтерпретує Helm:
> запустіть `env | grep ARXSENTINEL_METRICS_PASSWORD_HASH` всередину pod-а, щоб підтвердити цілісність хеша.

## Хмарні середовища (managed Kubernetes)

У керованих хмарних кластерах (EKS, GKE, AKS) вузли можуть не мати Fail2Ban або доступу
на рівні хоста до iptables. Підхід з логом загроз у hostPath не інтегрується з хмарними firewall API.

**Поточна рекомендація:** залишіть `threatLog.hostPath` порожнім і спостерігайте за подіями загроз
через endpoint метрик Prometheus. Блокуйте IP-адреси на рівні load balancer-а / WAF
на основі алертів Prometheus.

**Плануються:** Output Plugins (майбутній релиз) дозволять відправляти події загроз безпосередньо
у БД, чергу повідомлень, webhooks та хмарні firewall API — видаляючи залежність від Fail2Ban
для хмарних розгортань.

## Upgrade

```bash
helm upgrade arxsentinel ./deploy/container/k8s/arxsentinel
```

Pod-и автоматично перезавантажуються при зміні checksum ConfigMap.

## Uninstall

```bash
helm uninstall arxsentinel
```

Директорії hostPath на вузлах не видаляються — видаліть їх вручну при потребі.
