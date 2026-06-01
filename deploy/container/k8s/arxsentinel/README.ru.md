# ArxSentinel — Руководство по развёртыванию Helm-чарта

Helm-чарт ArxSentinel разворачивает DaemonSet, который запускает по одному pod-у на каждый узел,
читает лог доступа узла через `hostPath` и записывает события угроз в настраиваемую директорию хоста
для интеграции с Fail2Ban.

## Предварительные требования

- Helm 3.x
- Kubernetes 1.24+
- Docker-образ доступен из кластера (`ghcr.io/mr-addams/arxsentinel`)

## Быстрая установка

```bash
# Наблюдать за /var/log/nginx на каждом узле, только метрики (без Fail2Ban)
helm install arxsentinel ./deploy/container/k8s/arxsentinel \
  --set logVolume.hostPath=/var/log/nginx
```

## Полная установка — bare-metal / k3s с Fail2Ban

```bash
# Создать директорию логов угроз на каждом узле:
# (выполнить на каждом узле, или использовать init container в DaemonSet)
sudo mkdir -p /var/log/arxsentinel
sudo chown 65532:65532 /var/log/arxsentinel

helm install arxsentinel ./deploy/container/k8s/arxsentinel \
  --set logVolume.hostPath=/var/log/nginx \
  --set threatLog.hostPath=/var/log/arxsentinel
```

## Справочник Values

| Ключ | Тип | Дефолт | Описание |
|---|---|---|---|
| `image.repository` | string | `ghcr.io/mr-addams/arxsentinel` | Репозиторий образа |
| `image.tag` | string | `""` | Тег образа; по умолчанию `Chart.AppVersion` |
| `image.pullPolicy` | string | `IfNotPresent` | Политика загрузки образа |
| `logVolume.hostPath` | string | `/var/log/nginx` | Путь хоста, содержащий лог доступа |
| `logFile` | string | `access.log` | Имя файла лога доступа внутри `logVolume.hostPath` |
| `threatLog.hostPath` | string | `""` | Путь хоста для лога угроз; пусто = без mount-а hostPath |
| `metrics.enabled` | bool | `true` | Включить Prometheus-endpoint `/metrics` |
| `metrics.port` | int | `9117` | Порт метрик |
| `service.type` | string | `ClusterIP` | Тип Kubernetes Service |
| `serviceMonitor.enabled` | bool | `false` | Создать Prometheus Operator `ServiceMonitor` |
| `serviceMonitor.namespace` | string | `monitoring` | Namespace Prometheus Operator |
| `serviceMonitor.interval` | string | `30s` | Интервал скрейпинга |
| `resources.limits.cpu` | string | `200m` | Лимит CPU |
| `resources.limits.memory` | string | `128Mi` | Лимит памяти |
| `resources.requests.cpu` | string | `20m` | Запрос CPU |
| `resources.requests.memory` | string | `32Mi` | Запрос памяти |
| `tolerations` | list | `[]` | Tolerations для узлов |
| `nodeSelector` | object | `{}` | Селектор узлов |
| `env` | object | см. values.yaml | Переопределение переменных `ARXSENTINEL_*` |
| `extraEnv` | list | `[]` | Дополнительные переменные окружения (произвольные пары ключ/значение) |

## Интеграция с Fail2Ban (bare-metal / k3s)

Установите `threatLog.hostPath` в директорию, присутствующую на каждом узле.
Fail2Ban на хосте читает `threats.log` из этой директории:

```bash
helm upgrade arxsentinel ./deploy/container/k8s/arxsentinel \
  --set threatLog.hostPath=/var/log/arxsentinel
```

Настройте Fail2Ban на хосте:

```ini
# /etc/fail2ban/jail.d/arxsentinel.conf
[arxsentinel]
enabled  = true
filter   = arxsentinel
logpath  = /var/log/arxsentinel/threats.log
maxretry = 1
bantime  = 3600
```

Конфиги фильтров и jail: [`deploy/fail2ban/`](deploy/fail2ban/).

## Интеграция с Prometheus Operator (ServiceMonitor)

```bash
helm upgrade arxsentinel ./deploy/container/k8s/arxsentinel \
  --set serviceMonitor.enabled=true \
  --set serviceMonitor.namespace=monitoring \
  --set serviceMonitor.additionalLabels.release=prometheus
```

`ServiceMonitor` нацеливается на порт `metrics` (9117) на ClusterIP-service ArxSentinel.

## Наблюдение за узлами control-plane

По умолчанию pod-ы DaemonSet не планируются на узлы control-plane. Добавьте toleration:

```bash
helm upgrade arxsentinel ./deploy/container/k8s/arxsentinel \
  --set "tolerations[0].key=node-role.kubernetes.io/control-plane" \
  --set "tolerations[0].operator=Exists" \
  --set "tolerations[0].effect=NoSchedule"
```

## Переопределение конфигурации через переменные окружения

Значения `env` отображаются прямо на переменные окружения `ARXSENTINEL_*`.
Они имеют приоритет над ConfigMap-ом, отрендеренным в `config.yaml`:

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

> **Примечание:** Поля массивов (пути probe, конфиги ботов, дополнительные паттерны) не могут
> быть установлены через переменные окружения.
> Переопределите их, отредактировав ConfigMap или примонтировав отдельный конфиг-файл.

### Полный справочник переменных окружения

> Полные примеры со всеми YAML-only секциями: [`config.example.yaml`](../../../config.example.yaml) в корне репозитория.

Массивы отмечены **YAML-only** — настраивайте через ConfigMap `config.yaml` или примонтированный конфиг-файл.

#### General, logging, parser

| Переменная | Тип | Дефолт | Описание |
|---|---|---|---|
| `ARXSENTINEL_GENERAL_LOG_FILE` | string | `/var/log/nginx/access.log` | Путь к логу доступа |
| `ARXSENTINEL_GENERAL_PID_FILE` | string | `/tmp/arxsentinel.pid` | Путь к PID-файлу |
| `ARXSENTINEL_GENERAL_LINES_BUF_SIZE` | int | `1000` | Размер буфера канала |
| `ARXSENTINEL_GENERAL_TAIL_RETRY_INTERVAL` | duration | `5s` | Интервал retry для tail |
| `ARXSENTINEL_GENERAL_STATS_INTERVAL` | duration | `300s` | Интервал лога статистики |
| `ARXSENTINEL_LOGGING_DEBUG` | bool | `false` | Включить debug-теги логирования |
| `ARXSENTINEL_LOGGING_CONSOLE_COLOR` | bool | `false` | Цветной вывод ANSI |
| `ARXSENTINEL_PARSER_PROFILE` | string | `` | Профиль сервера (apache, caddy, traefik, haproxy-http) |
| `ARXSENTINEL_PARSER_LOG_FORMAT` | string | `combined` | Формат лога (combined, json, regex) |
| `ARXSENTINEL_PARSER_REGEX_PATTERN` | string | `` | Go regex (обязателен для regex-формата) |
| `ARXSENTINEL_PARSER_TIMEZONE` | string | `UTC` | Timezone (зарезервирован) |
| `ARXSENTINEL_PARSER_JSON_REMOTE_ADDR` | string | `remote_addr` | JSON-ключ → client IP (log_format=json) |
| `ARXSENTINEL_PARSER_JSON_TIME` | string | `time_iso8601` | JSON-ключ → timestamp |
| `ARXSENTINEL_PARSER_JSON_REQUEST` | string | `request` | JSON-ключ → request line |
| `ARXSENTINEL_PARSER_JSON_STATUS` | string | `status` | JSON-ключ → HTTP status |
| `ARXSENTINEL_PARSER_JSON_BYTES_SENT` | string | `bytes_sent` | JSON-ключ → размер ответа |
| `ARXSENTINEL_PARSER_JSON_REFERER` | string | `http_referer` | JSON-ключ → заголовок Referer |
| `ARXSENTINEL_PARSER_JSON_USER_AGENT` | string | `http_user_agent` | JSON-ключ → заголовок User-Agent |
| `ARXSENTINEL_PARSER_JSON_REAL_IP` | string | `real_ip` | JSON-ключ → реальный IP клиента (за прокси) |

#### Scoring and state

| Переменная | Тип | Дефолт | Описание |
|---|---|---|---|
| `ARXSENTINEL_SCORING_ALERT_THRESHOLD` | int | `50` | Порог WARN |
| `ARXSENTINEL_SCORING_BAN_THRESHOLD` | int | `80` | Порог THREAT (ban) |
| `ARXSENTINEL_SCORING_OBSERVATION_WINDOW` | duration | `300s` | Окно распада очков |
| `ARXSENTINEL_SCORING_DECAY` | string | `linear` | Алгоритм распада (YAML-only) |
| `ARXSENTINEL_STATE_GC_INTERVAL` | duration | `60s` | Интервал GC |
| `ARXSENTINEL_STATE_MAX_TRACKED_IPS` | int | `100000` | Макс. отслеживаемых IP |

#### Detectors — probe, bruteforce, crawler, no-asset

| Переменная | Тип | Дефолт | Описание |
|---|---|---|---|
| `ARXSENTINEL_DETECTORS_PROBE_ENABLED` | bool | `true` | Включить probe scanner |
| `ARXSENTINEL_DETECTORS_PROBE_SCORE` | int | `25` | Очки за попадание на probe-путь |
| `ARXSENTINEL_DETECTORS_PROBE_PATHS` | array | _(29 путей)_ | **YAML-only** |
| `ARXSENTINEL_DETECTORS_BRUTEFORCE_ENABLED` | bool | `true` | Включить bruteforce по 404-ratio |
| `ARXSENTINEL_DETECTORS_BRUTEFORCE_MIN_REQUESTS` | int | `10` | Мин. запросов перед проверкой |
| `ARXSENTINEL_DETECTORS_BRUTEFORCE_RATIO_THRESHOLD` | float | `0.6` | Порог 404-ratio |
| `ARXSENTINEL_DETECTORS_BRUTEFORCE_SCORE` | int | `30` | Очки за bruteforce |
| `ARXSENTINEL_DETECTORS_CRAWLER_ENABLED` | bool | `true` | Включить sequential crawler |
| `ARXSENTINEL_DETECTORS_CRAWLER_MIN_SEQUENTIAL` | int | `5` | Мин. последовательных запросов |
| `ARXSENTINEL_DETECTORS_CRAWLER_SCORE` | int | `20` | Очки за crawler |
| `ARXSENTINEL_DETECTORS_NOASSET_ENABLED` | bool | `true` | Включить no-asset bot |
| `ARXSENTINEL_DETECTORS_NOASSET_MIN_PAGE_REQUESTS` | int | `3` | Мин. page-запросов |
| `ARXSENTINEL_DETECTORS_NOASSET_ASSET_RATIO_THRESHOLD` | float | `0.1` | Порог asset-ratio |
| `ARXSENTINEL_DETECTORS_NOASSET_SCORE` | int | `20` | Очки за no-asset |
| `ARXSENTINEL_DETECTORS_NOASSET_ASSET_EXTENSIONS` | array | _(12 расширений)_ | **YAML-only** |

#### Detectors — rate, user-agent, overflow, badbot

| Переменная | Тип | Дефолт | Описание |
|---|---|---|---|
| `ARXSENTINEL_DETECTORS_RATE_ENABLED` | bool | `true` | Включить rate anomaly |
| `ARXSENTINEL_DETECTORS_RATE_WINDOW` | duration | `60s` | Окно подсчёта rate |
| `ARXSENTINEL_DETECTORS_RATE_THRESHOLD` | int | `100` | Запросов в окне |
| `ARXSENTINEL_DETECTORS_RATE_SCORE` | int | `25` | Очки за rate |
| `ARXSENTINEL_DETECTORS_USERAGENT_ENABLED` | bool | `true` | Включить UA anomaly |
| `ARXSENTINEL_DETECTORS_USERAGENT_SCANNER_SCORE` | int | `40` | Очки за scanner UA |
| `ARXSENTINEL_DETECTORS_USERAGENT_GRABBER_SCORE` | int | `20` | Очки за grabber UA |
| `ARXSENTINEL_DETECTORS_USERAGENT_AUTOMATION_SCORE` | int | `15` | Очки за automation tool UA |
| `ARXSENTINEL_DETECTORS_USERAGENT_EMPTY_UA_SCORE` | int | `30` | Очки за empty UA |
| `ARXSENTINEL_DETECTORS_USERAGENT_EXTRA_SCANNER_PATTERNS` | array | `[]` | **YAML-only** |
| `ARXSENTINEL_DETECTORS_USERAGENT_EXTRA_GRABBER_PATTERNS` | array | `[]` | **YAML-only** |
| `ARXSENTINEL_DETECTORS_USERAGENT_EXTRA_AUTOMATION_PATTERNS` | array | `[]` | **YAML-only** |
| `ARXSENTINEL_DETECTORS_OVERFLOW_ENABLED` | bool | `true` | Включить overflow/WAF bypass |
| `ARXSENTINEL_DETECTORS_OVERFLOW_MAX_URL_LENGTH` | int | `2048` | Порог длины URL |
| `ARXSENTINEL_DETECTORS_OVERFLOW_SCORE` | int | `30` | Очки за overflow |
| `ARXSENTINEL_DETECTORS_OVERFLOW_SUSPICIOUS_PARAMS` | array | _(7 параметров)_ | **YAML-only** |
| `ARXSENTINEL_DETECTORS_BADBOT_ENABLED` | bool | `true` | Включить community blocklist |
| `ARXSENTINEL_DETECTORS_BADBOT_SCORE` | int | `60` | Очки за совпадение в blocklist |
| `ARXSENTINEL_DETECTORS_BADBOT_CHECK_UA` | bool | `true` | Проверять UA против badbot-ua |
| `ARXSENTINEL_DETECTORS_BADBOT_CHECK_REFERRER` | bool | `false` | Проверять Referer против badbot-ref |

#### Whitelist, chain guard, output, metrics

| Переменная | Тип | Дефолт | Описание |
|---|---|---|---|
| `ARXSENTINEL_WHITELIST_FAKE_BOT_SCORE` | int | `35` | Штраф за fake bot |
| `ARXSENTINEL_WHITELIST_DNS_VERIFY_TIMEOUT` | duration | `2s` | Timeout для DNS-проверки бота |
| `ARXSENTINEL_WHITELIST_DNS_CACHE_POSITIVE_TTL` | duration | `24h` | Positive DNS cache TTL |
| `ARXSENTINEL_WHITELIST_DNS_CACHE_NEGATIVE_TTL` | duration | `1h` | Negative DNS cache TTL |
| `ARXSENTINEL_WHITELIST_DNS_CACHE_IP_LIST_REFRESH` | duration | `24h` | Интервал обновления диапазонов IP ботов |
| `ARXSENTINEL_WHITELIST_CUSTOM_IPS` | CSV | `` | Доверенные IP (через запятую) |
| `ARXSENTINEL_WHITELIST_CUSTOM_CIDRS` | CSV | `` | Доверенные подсети (через запятую) |
| `ARXSENTINEL_WHITELIST_BOTS` | array | _(11 ботов)_ | **YAML-only** |
| `ARXSENTINEL_CHAIN_GUARD_ENABLED` | bool | `false` | Включить проверку proxy chain |
| `ARXSENTINEL_CHAIN_GUARD_WARNINGS_LOG` | string | `` | Путь к логу предупреждений |
| `ARXSENTINEL_CHAIN_GUARD_CLOUDFLARE_ENABLED` | bool | `true` | Включить проверку IP-диапазонов Cloudflare |
| `ARXSENTINEL_CHAIN_GUARD_CLOUDFLARE_REFRESH_INTERVAL` | duration | `24h` | Интервал обновления IP-списка Cloudflare |
| `ARXSENTINEL_CHAIN_GUARD_BOGON_ENABLED` | bool | `true` | Включить проверку bogon/RFC1918/CGNAT |
| `ARXSENTINEL_BLOCKLIST_STORAGE` | string | `` | Путь для персистентного кэша blocklist |
| `ARXSENTINEL_OUTPUT_THREAT_LOG` | string | `/var/log/arxsentinel/threats.log` | Путь к логу угроз |
| `ARXSENTINEL_OUTPUT_OPERATIONAL_LOG` | string | `/var/log/arxsentinel/sentinel.log` | Путь к операционному логу |
| `ARXSENTINEL_METRICS_ENABLED` | bool | `false` | Включить Prometheus-endpoint |
| `ARXSENTINEL_METRICS_LISTEN_ADDR` | string | `:9117` | Адрес слушания для метрик |
| `ARXSENTINEL_METRICS_USERNAME` | string | `` | Юзер для basic auth |
| `ARXSENTINEL_METRICS_PASSWORD_HASH` | string | `` | bcrypt-хэш пароля |
| `ARXSENTINEL_PIPELINE_BUFFER_SIZE` | int | `8192` | Глубина буфера канала (увеличить для burst-трафика) |
| `ARXSENTINEL_PIPELINE_SHUTDOWN_TIMEOUT` | duration | `15s` | Окно graceful shutdown |

### Basic auth для метрик

Когда настроен basic auth для метрик, поле `ARXSENTINEL_METRICS_PASSWORD_HASH`
должно содержать **bcrypt-хэш** (не простой пароль). Создайте его с помощью:

```bash
htpasswd -bnBC 10 "" your-password | tr -d ':\n'
```

Пример values.yaml:

```yaml
env:
  ARXSENTINEL_METRICS_USERNAME: "prometheus"
  ARXSENTINEL_METRICS_PASSWORD_HASH: "$2y$10$..."
```

> **Предупреждение:** В Helm values, знаки `$` в bcrypt-хэше должны быть экранированы
> или обёрнуты в одинарные кавычки, чтобы Helm не интерпретировал их как templating.
> Используйте `$2y$10$...` непосредственно в `values.yaml` — Helm правильно обрабатывает raw `$` в простых env vars.
> Если возникают ошибки рендеринга, проверьте, что хэш не содержит символов, которые интерпретирует Helm:
> выполните `env | grep ARXSENTINEL_METRICS_PASSWORD_HASH` внутри pod-а, чтобы подтвердить целостность хэша.

## Облачные окружения (managed Kubernetes)

В управляемых облачных кластерах (EKS, GKE, AKS) узлы могут не иметь Fail2Ban или доступа
на уровне хоста к iptables. Подход с threat log в hostPath не интегрируется с облачными firewall API.

**Текущая рекомендация:** оставьте `threatLog.hostPath` пустым и отслеживайте события угроз
через Prometheus-endpoint метрик. Блокируйте IP-адреса на уровне load balancer-а / WAF
на основе Prometheus-алертов.

**Планируется:** Output Plugins (будущий релиз) позволят отправлять события угроз напрямую
в БД, очереди сообщений, webhooks и облачные firewall API — удаляя зависимость от Fail2Ban
для облачных deployments.

## Upgrade

```bash
helm upgrade arxsentinel ./deploy/container/k8s/arxsentinel
```

Pod-ы перезагружаются автоматически при изменении checksum ConfigMap.

## Uninstall

```bash
helm uninstall arxsentinel
```

Директории hostPath на узлах не удаляются — удалите их вручную при необходимости.
