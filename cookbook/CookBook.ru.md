# ArxSentinel — Книга рецептов

> 🌐 [English](CookBook.md) | [Українська](CookBook.uk.md)

Готовые к использованию конфигурации для типовых сценариев развёртывания.
Скопируйте файл, соответствующий вашему окружению, заполните переменные и запускайте.

## Структура конфигурации

Каждый рецепт соответствует порядку пайплайна ArxSentinel:

```
Sources → Processors → Sinks → Executors
```

| Секция | Назначение | Обязательно |
|--------|------------|-------------|
| `streams.inputs` | Источники логов | ✅ |
| `scoring` | Пороги угроз | ✅ |
| `detectors` | 8 встроенных процессоров | ✅ |
| `whitelist.custom` | Доверенные IP/CIDR/UA/Paths | ✅ |
| `chain_guard` | Целостность прокси-цепочки | опционально |
| `streams.outputs` | Приёмники событий | ✅ |
| `executors` | Автоматизированный ответ | только рецепты с executor |
| [config.reference.yaml](config.reference.yaml) | Полный справочник всех параметров | — |

## Содержание

- [Fail2Ban (file-based logging)](#fail2ban)
- [Syslog (сетевой транспорт логов)](#syslog)
- [HTTP-источник (push/pull приёмник логов)](#http)
- [Cloudflare Executor (автоматическая блокировка IP)](#cloudflare)
- [MikroTik Executor (address-list на RouterOS)](#mikrotik)
- [Nginx Executor (файл блокировки + перезагрузка)](#nginx-executor)
- [Инфраструктура: Конфигурации серверов](#server-configs)
- [Инфраструктура: Обратный прокси / Real-IP](#reverse-proxy)
- [Инфраструктура: Kubernetes](#kubernetes)

---

## Fail2Ban

Записывает события угроз в лог-файл. Fail2Ban читает его и блокирует IP через iptables/nftables.
Executor не требуется — работает с любым Fail2Ban jail сразу после установки.

| Рецепт | Описание | Файл |
|--------|----------|------|
| nginx basic | Один сайт на nginx, комбинированный формат лога | [fail2ban/nginx-basic.yaml](fail2ban/nginx-basic.yaml) |
| nginx multi-stream | Два nginx vhost с общим логом угроз | [fail2ban/nginx-multi-stream.yaml](fail2ban/nginx-multi-stream.yaml) |
| nginx + WordPress | Специфичные WordPress пути зондирования | [fail2ban/nginx-wordpress.yaml](fail2ban/nginx-wordpress.yaml) |
| nginx + Laravel | Специфичные Laravel пути зондирования | [fail2ban/nginx-laravel.yaml](fail2ban/nginx-laravel.yaml) |
| nginx + Drupal | Специфичные Drupal пути зондирования | [fail2ban/nginx-drupal.yaml](fail2ban/nginx-drupal.yaml) |
| Apache | Apache Combined Log Format | [fail2ban/apache.yaml](fail2ban/apache.yaml) |
| Caddy | Caddy transform-encoder формат лога | [fail2ban/caddy.yaml](fail2ban/caddy.yaml) |
| HAProxy | HAProxy httplog через rsyslog | [fail2ban/haproxy.yaml](fail2ban/haproxy.yaml) |
| Traefik | Traefik CLF access log | [fail2ban/traefik.yaml](fail2ban/traefik.yaml) |
| LiteSpeed | LiteSpeed / OpenLiteSpeed access log | [fail2ban/litespeed.yaml](fail2ban/litespeed.yaml) |

### Docker

Docker Compose stack для запуска ArxSentinel + Fail2Ban в контейнерах.

| Файл | Назначение |
|------|------------|
| [fail2ban/docker/config.yaml](fail2ban/docker/config.yaml) | Конфигурация ArxSentinel для Docker |
| [fail2ban/docker/docker-compose.yml](fail2ban/docker/docker-compose.yml) | Compose stack: arxsentinel + fail2ban |

---

## Syslog (сетевой транспорт логов)

Получение логов nginx (или любого веб-сервера) напрямую по сети через встроенный
syslog-источник. Нет общих лог-файлов, нет ротации логов, нет монтирования томов.
nginx отправляет строки access-логов в ArxSentinel по UDP или TCP — ArxSentinel слушает,
извлекает строку лога из syslog-конверта и обрабатывает обычным образом.

**Конфигурация nginx** (добавить в `nginx.conf` или блок сайта):
```nginx
access_log syslog:server=127.0.0.1:5514,facility=local7,tag=nginx,severity=info combined;
```

**Когда использовать syslog вместо file:**
- Контейнеризированные развёртывания, где общие тома неудобны
- Несколько nginx worker на разных хостах, отправляющих логи на один ArxSentinel
- Окружения, где лог-файлы не сохраняются (эфемерные контейнеры, read-only fs)
- Интеграция с rsyslog / syslog-ng для пайплайнов агрегации логов

| Рецепт | Описание | Файл |
|--------|----------|------|
| nginx + Fail2Ban | UDP syslog → ArxSentinel → threats.log | [syslog/nginx-fail2ban.yaml](syslog/nginx-fail2ban.yaml) |
| nginx + Cloudflare | UDP syslog → ArxSentinel → автоматическая блокировка Cloudflare | [syslog/nginx-cloudflare.yaml](syslog/nginx-cloudflare.yaml) |
| nginx multi-stream | Два vhost на разных syslog-портах | [syslog/nginx-multi-stream.yaml](syslog/nginx-multi-stream.yaml) |
| HAProxy | UDP syslog → ArxSentinel → threats.log (встроенный syslog-клиент HAProxy) | [syslog/haproxy.yaml](syslog/haproxy.yaml) |
| Traefik | rsyslog-ретрансляция → ArxSentinel → threats.log | [syslog/traefik.yaml](syslog/traefik.yaml) |
| Caddy | UDP syslog (net logger) → ArxSentinel → threats.log | [syslog/caddy.yaml](syslog/caddy.yaml) |
| LiteSpeed | rsyslog-ретрансляция → ArxSentinel → threats.log | [syslog/litespeed.yaml](syslog/litespeed.yaml) |

### Docker

Docker Compose с нулевым объёмом: nginx отправляет логи в контейнер ArxSentinel
через внутреннюю сеть Docker — общий том не требуется.

| Файл | Назначение |
|------|------------|
| [syslog/docker/config.yaml](syslog/docker/config.yaml) | Конфигурация ArxSentinel для syslog Docker |
| [syslog/docker/docker-compose.yml](syslog/docker/docker-compose.yml) | Compose stack: nginx → syslog → arxsentinel |

---

## HTTP (HTTP/HTTPS приёмник логов)

HTTP/HTTPS источник логов с поддержкой 9 push-протоколов и pull-режима.
Используйте, когда вендоры отправляют логи напрямую в ArxSentinel по HTTP.

**Когда использовать HTTP-источник:**
- Cloudflare Logpush, AWS Firehose, GCP Pub/Sub push
- Loki push API, OTLP HTTP логи, Azure Monitor export, Splunk HEC
- NDJSON потоки с извлечением полей
- Опрос удалённых endpoint'ов (pull-режим)
- Приём логов по HTTPS с TLS

| Рецепт | Описание | Файл |
|--------|----------|------|
| Полный справочник с примерами | 9 протоколов + pull + TLS | [http/CookBook.ru.md](http/CookBook.ru.md) |

---

## Cloudflare

ArxSentinel отправляет события THREAT в Cloudflare API для блокировки IP через firewall rules.
Требуется токен Cloudflare API с правом Account → IP Lists → Edit.

| Рецепт | Описание | Файл |
|--------|----------|------|
| nginx basic | Один сайт nginx + блокировка через Cloudflare | [cloudflare/nginx-basic.yaml](cloudflare/nginx-basic.yaml) |
| nginx multi-stream | Два nginx vhost, общий Cloudflare executor | [cloudflare/nginx-multi-stream.yaml](cloudflare/nginx-multi-stream.yaml) |
| nginx + WordPress | Пути WordPress + блокировка через Cloudflare | [cloudflare/nginx-wordpress.yaml](cloudflare/nginx-wordpress.yaml) |
| Traefik | Traefik access log + блокировка через Cloudflare | [cloudflare/traefik.yaml](cloudflare/traefik.yaml) |

### Docker

| Файл | Назначение |
|------|------------|
| [cloudflare/docker/config.yaml](cloudflare/docker/config.yaml) | Конфигурация ArxSentinel для Docker + Cloudflare |
| [cloudflare/docker/docker-compose.yml](cloudflare/docker/docker-compose.yml) | Compose stack: arxsentinel с Cloudflare executor |

---

## MikroTik

ArxSentinel отправляет события THREAT в MikroTik RouterOS REST API для добавления IP в address-list.
Требуется RouterOS 7.x с включённым REST API.

| Рецепт | Описание | Файл |
|--------|----------|------|
| nginx basic | Один сайт nginx + MikroTik address-list | [mikrotik/nginx-basic.yaml](mikrotik/nginx-basic.yaml) |
| nginx multi-stream | Два nginx vhost, общий MikroTik executor | [mikrotik/nginx-multi-stream.yaml](mikrotik/nginx-multi-stream.yaml) |

### Docker

| Файл | Назначение |
|------|------------|
| [mikrotik/docker/config.yaml](mikrotik/docker/config.yaml) | Конфигурация ArxSentinel для Docker + MikroTik |
| [mikrotik/docker/docker-compose.yml](mikrotik/docker/docker-compose.yml) | Compose stack: arxsentinel с MikroTik executor |

---

## Nginx Executor

ArxSentinel записывает IP угроз в файл блокировки, совместимый с nginx, и инициирует перезагрузку.
Никаких внешних зависимостей — чистый nginx geo + map.

| Рецепт | Описание | Файл |
|--------|----------|------|
| nginx basic | Один сайт nginx + перезагрузка блоклиста | [nginx-executor/nginx-basic.yaml](nginx-executor/nginx-basic.yaml) |

### Docker

| Файл | Назначение |
|------|------------|
| [nginx-executor/docker/config.yaml](nginx-executor/docker/config.yaml) | Конфигурация ArxSentinel для Docker + nginx executor |
| [nginx-executor/docker/docker-compose.yml](nginx-executor/docker/docker-compose.yml) | Compose stack: arxsentinel с nginx blocklist reload |

---

## Конфигурации серверов

Фрагменты для настройки вашего веб-сервера для генерации логов, которые ArxSentinel может анализировать.

| Файл | Назначение |
|------|------------|
| [server-configs/nginx-json-logformat.conf](server-configs/nginx-json-logformat.conf) | JSON формат лога для nginx (структурированный парсинг) |
| [server-configs/apache-httpd.conf](server-configs/apache-httpd.conf) | Combined log format для Apache httpd |
| [server-configs/Caddyfile](server-configs/Caddyfile) | transform-encoder конфигурация для Caddy access log |
| [server-configs/haproxy.cfg](server-configs/haproxy.cfg) | httplog формат для HAProxy |
| [server-configs/litespeed-httpd.conf](server-configs/litespeed-httpd.conf) | Combined log format для LiteSpeed |

---

## Обратный прокси / Real-IP

Когда ArxSentinel работает за обратным прокси, IP клиента в логе может быть IP прокси
вместо реального посетителя. Эти конфигурации исправляют это.

| Схема | Конфигурация прокси | Конфигурация nginx (origin) |
|-------|---------------------|------------------------------|
| nginx за nginx | [reverse-proxy/nginx-rp/nginx-upstream.conf](reverse-proxy/nginx-rp/nginx-upstream.conf) | [reverse-proxy/nginx-rp/nginx-origin.conf](reverse-proxy/nginx-rp/nginx-origin.conf) |
| nginx за Caddy | [reverse-proxy/caddy/Caddyfile](reverse-proxy/caddy/Caddyfile) | [reverse-proxy/caddy/nginx.conf](reverse-proxy/caddy/nginx.conf) |
| nginx за HAProxy | [reverse-proxy/haproxy/haproxy.cfg](reverse-proxy/haproxy/haproxy.cfg) | [reverse-proxy/haproxy/nginx.conf](reverse-proxy/haproxy/nginx.conf) |
| nginx за Traefik | [reverse-proxy/traefik/traefik.yml](reverse-proxy/traefik/traefik.yml) | [reverse-proxy/traefik/nginx.conf](reverse-proxy/traefik/nginx.conf) |

---

## Kubernetes

| Файл | Назначение |
|------|------------|
| [kubernetes/daemonset.yaml](kubernetes/daemonset.yaml) | DaemonSet: один ArxSentinel на узел, чтение хостовых логов |
| [kubernetes/sidecar.yaml](kubernetes/sidecar.yaml) | Sidecar: один ArxSentinel на pod, чтение контейнерных логов |
| [kubernetes/configmap.yaml](kubernetes/configmap.yaml) | ConfigMap с типовой конфигурацией ArxSentinel |