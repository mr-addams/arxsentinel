# ArxSentinel — Книга рецептів

> 🌐 [English](CookBook.md) | [Русский](CookBook.ru.md)

Готові до використання конфігурації для типових сценаріїв розгортання.
Скопіюйте файл, що відповідає вашому середовищу, заповніть змінні та запускайте.

## Структура конфігурації

Кожен рецепт відповідає порядку пайплайну ArxSentinel:

```
Sources → Processors → Sinks → Executors
```

| Секція | Призначення | Обов'язково |
|--------|-------------|-------------|
| `streams.inputs` | Джерела логів | ✅ |
| `scoring` | Пороги загроз | ✅ |
| `detectors` | 8 вбудованих процесорів | ✅ |
| `whitelist.custom` | Довірені IP/CIDR/UA/Paths | ✅ |
| `chain_guard` | Цілісність проксі-ланцюжка | опційно |
| `streams.outputs` | Приймачі подій | ✅ |
| `executors` | Автоматизована відповідь | лише рецепти з executor |
| [config.reference.yaml](config.reference.yaml) | Повний довідник всіх параметрів | — |

## Зміст

- [Fail2Ban (file-based logging)](#fail2ban)
- [Syslog (мережевий транспорт логів)](#syslog)
- [HTTP-джерело (push/pull приймач логів)](#http)
- [Cloudflare Executor (автоматичне блокування IP)](#cloudflare)
- [MikroTik Executor (address-list на RouterOS)](#mikrotik)
- [OpenWrt Executor (ubus/UCI firewall)](#openwrt)
- [OPNsense Executor (REST API alias)](#opnsense)
- [Nginx Executor (файл блокування + перезавантаження)](#nginx-executor)
- [Інфраструктура: Конфігурації серверів](#server-configs)
- [Інфраструктура: Зворотній проксі / Real-IP](#reverse-proxy)
- [Інфраструктура: Kubernetes](#kubernetes)
- [Інфраструктура: Розгортання на FreeBSD](#розгортання-на-freebsd)

---

## Fail2Ban

Записує події загроз у лог-файл. Fail2Ban читає його і блокує IP через iptables/nftables.
Executor не потрібен — працює з будь-яким Fail2Ban jail одразу після встановлення.

| Рецепт | Опис | Файл |
|--------|------|------|
| nginx basic | Один сайт на nginx, комбінований формат логу | [fail2ban/nginx-basic.yaml](fail2ban/nginx-basic.yaml) |
| nginx multi-stream | Два nginx vhost зі спільним логом загроз | [fail2ban/nginx-multi-stream.yaml](fail2ban/nginx-multi-stream.yaml) |
| nginx + WordPress | Специфічні WordPress шляхи зондування | [fail2ban/nginx-wordpress.yaml](fail2ban/nginx-wordpress.yaml) |
| nginx + Laravel | Специфічні Laravel шляхи зондування | [fail2ban/nginx-laravel.yaml](fail2ban/nginx-laravel.yaml) |
| nginx + Drupal | Специфічні Drupal шляхи зондування | [fail2ban/nginx-drupal.yaml](fail2ban/nginx-drupal.yaml) |
| Apache | Apache Combined Log Format | [fail2ban/apache.yaml](fail2ban/apache.yaml) |
| Caddy | Caddy transform-encoder формат логу | [fail2ban/caddy.yaml](fail2ban/caddy.yaml) |
| HAProxy | HAProxy httplog через rsyslog | [fail2ban/haproxy.yaml](fail2ban/haproxy.yaml) |
| Traefik | Traefik CLF access log | [fail2ban/traefik.yaml](fail2ban/traefik.yaml) |
| LiteSpeed | LiteSpeed / OpenLiteSpeed access log | [fail2ban/litespeed.yaml](fail2ban/litespeed.yaml) |

### Docker

Docker Compose stack для запуску ArxSentinel + Fail2Ban в контейнерах.

| Файл | Призначення |
|------|-------------|
| [fail2ban/docker/config.yaml](fail2ban/docker/config.yaml) | Конфігурація ArxSentinel для Docker |
| [fail2ban/docker/docker-compose.yml](fail2ban/docker/docker-compose.yml) | Compose stack: arxsentinel + fail2ban |

---

## Syslog (мережевий транспорт логів)

Отримання логів nginx (або будь-якого веб-сервера) безпосередньо по мережі через
вбудований syslog-джерело. Жодних спільних лог-файлів, жодної ротації логів,
жодного монтування томів. nginx надсилає рядки access-логів до ArxSentinel
по UDP або TCP — ArxSentinel слухає, вилучає рядок логу з syslog-конверта
та обробляє звичайним чином.

**Конфігурація nginx** (додати в `nginx.conf` або блок сайту):
```nginx
access_log syslog:server=127.0.0.1:5514,facility=local7,tag=nginx,severity=info combined;
```

**Коли використовувати syslog замість file:**
- Контейнеризовані розгортання, де спільні томи незручні
- Кілька nginx worker на різних хостах, що надсилають логи на один ArxSentinel
- Середовища, де лог-файли не зберігаються (ефемерні контейнери, read-only fs)
- Інтеграція з rsyslog / syslog-ng для пайплайнів агрегації логів

| Рецепт | Опис | Файл |
|--------|------|------|
| nginx + Fail2Ban | UDP syslog → ArxSentinel → threats.log | [syslog/nginx-fail2ban.yaml](syslog/nginx-fail2ban.yaml) |
| nginx + Cloudflare | UDP syslog → ArxSentinel → автоматичне блокування Cloudflare | [syslog/nginx-cloudflare.yaml](syslog/nginx-cloudflare.yaml) |
| nginx multi-stream | Два vhost на різних syslog-портах | [syslog/nginx-multi-stream.yaml](syslog/nginx-multi-stream.yaml) |
| HAProxy | UDP syslog → ArxSentinel → threats.log (вбудований syslog-клієнт HAProxy) | [syslog/haproxy.yaml](syslog/haproxy.yaml) |
| Traefik | rsyslog-ретрансляція → ArxSentinel → threats.log | [syslog/traefik.yaml](syslog/traefik.yaml) |
| Caddy | UDP syslog (net logger) → ArxSentinel → threats.log | [syslog/caddy.yaml](syslog/caddy.yaml) |
| LiteSpeed | rsyslog-ретрансляція → ArxSentinel → threats.log | [syslog/litespeed.yaml](syslog/litespeed.yaml) |

### Docker

Docker Compose з нульовим об'ємом: nginx надсилає логи до контейнера ArxSentinel
через внутрішню мережу Docker — спільний том не потрібен.

| Файл | Призначення |
|------|-------------|
| [syslog/docker/config.yaml](syslog/docker/config.yaml) | Конфігурація ArxSentinel для syslog Docker |
| [syslog/docker/docker-compose.yml](syslog/docker/docker-compose.yml) | Compose stack: nginx → syslog → arxsentinel |

---

## HTTP (HTTP/HTTPS приймач логів)

HTTP/HTTPS джерело логів з підтримкою 9 push-протоколів та pull-режиму.
Використовуйте, коли вендори надсилають логи безпосередньо до ArxSentinel через HTTP.

**Коли використовувати HTTP-джерело:**
- Cloudflare Logpush, AWS Firehose, GCP Pub/Sub push
- Loki push API, OTLP HTTP логи, Azure Monitor export, Splunk HEC
- NDJSON потоки з вилученням полів
- Опитування віддалених endpoint'ів (pull-режим)
- Прийом логів через HTTPS з TLS

| Рецепт | Опис | Файл |
|--------|------|------|
| Повний довідник з прикладами | 9 протоколів + pull + TLS | [http/CookBook.uk.md](http/CookBook.uk.md) |

---

## Cloudflare

ArxSentinel надсилає події THREAT до Cloudflare API для блокування IP через firewall rules.
Потрібен токен Cloudflare API з правом Account → IP Lists → Edit.

| Рецепт | Опис | Файл |
|--------|------|------|
| nginx basic | Один сайт nginx + блокування через Cloudflare | [cloudflare/nginx-basic.yaml](cloudflare/nginx-basic.yaml) |
| nginx multi-stream | Два nginx vhost, спільний Cloudflare executor | [cloudflare/nginx-multi-stream.yaml](cloudflare/nginx-multi-stream.yaml) |
| nginx + WordPress | Шляхи WordPress + блокування через Cloudflare | [cloudflare/nginx-wordpress.yaml](cloudflare/nginx-wordpress.yaml) |
| Traefik | Traefik access log + блокування через Cloudflare | [cloudflare/traefik.yaml](cloudflare/traefik.yaml) |

### Docker

| Файл | Призначення |
|------|-------------|
| [cloudflare/docker/config.yaml](cloudflare/docker/config.yaml) | Конфігурація ArxSentinel для Docker + Cloudflare |
| [cloudflare/docker/docker-compose.yml](cloudflare/docker/docker-compose.yml) | Compose stack: arxsentinel з Cloudflare executor |

---

## MikroTik

ArxSentinel надсилає події THREAT до MikroTik RouterOS REST API для додавання IP до address-list.
Потрібен RouterOS 7.x з увімкненим REST API.

| Рецепт | Опис | Файл |
|--------|------|------|
| nginx basic | Один сайт nginx + MikroTik address-list | [mikrotik/nginx-basic.yaml](mikrotik/nginx-basic.yaml) |
| nginx multi-stream | Два nginx vhost, спільний MikroTik executor | [mikrotik/nginx-multi-stream.yaml](mikrotik/nginx-multi-stream.yaml) |

### Docker

| Файл | Призначення |
|------|-------------|
| [mikrotik/docker/config.yaml](mikrotik/docker/config.yaml) | Конфігурація ArxSentinel для Docker + MikroTik |
| [mikrotik/docker/docker-compose.yml](mikrotik/docker/docker-compose.yml) | Compose stack: arxsentinel з MikroTik executor |

---

## OpenWrt

ArxSentinel надсилає події THREAT до ubus/UCI firewall роутера OpenWrt для додавання IP до іменованого ipset.
Потрібні `uhttpd-mod-ubus`, core-плагіни `rpcd` (`uci`, `rc`) та заздалегідь оголошена секція ipset в UCI.

| Рецепт | Опис | Файл |
|--------|------|------|
| nginx basic | Один сайт nginx + OpenWrt ipset | [openwrt/nginx-basic.yaml](openwrt/nginx-basic.yaml) |

---

## OPNsense

ArxSentinel надсилає події THREAT до REST API фаєрвола OPNsense для додавання IP до заздалегідь оголошеного аліасу.
Потрібні аліас типу `Host`, `Network` або `External` (Firewall → Aliases) та пара API-ключів, згенерована у System → Access → Users → API keys.

| Рецепт | Опис | Файл |
|--------|------|------|
| nginx basic | Один сайт nginx + OPNsense alias | [opnsense/nginx-basic.yaml](opnsense/nginx-basic.yaml) |

---

## Nginx Executor

ArxSentinel записує IP загроз у файл блокування сумісний з nginx та ініціює перезавантаження.
Жодних зовнішніх залежностей — чистий nginx geo + map.

| Рецепт | Опис | Файл |
|--------|------|------|
| nginx basic | Один сайт nginx + перезавантаження блоклиста | [nginx-executor/nginx-basic.yaml](nginx-executor/nginx-basic.yaml) |

### Docker

| Файл | Призначення |
|------|-------------|
| [nginx-executor/docker/config.yaml](nginx-executor/docker/config.yaml) | Конфігурація ArxSentinel для Docker + nginx executor |
| [nginx-executor/docker/docker-compose.yml](nginx-executor/docker/docker-compose.yml) | Compose stack: arxsentinel з nginx blocklist reload |

---

## Конфігурації серверів

Фрагменти для налаштування вашого веб-сервера для створення логів, які ArxSentinel може аналізувати.

| Файл | Призначення |
|------|-------------|
| [server-configs/nginx-json-logformat.conf](server-configs/nginx-json-logformat.conf) | JSON формат логу для nginx (структурований парсинг) |
| [server-configs/apache-httpd.conf](server-configs/apache-httpd.conf) | Combined log format для Apache httpd |
| [server-configs/Caddyfile](server-configs/Caddyfile) | transform-encoder конфігурація для Caddy access log |
| [server-configs/haproxy.cfg](server-configs/haproxy.cfg) | httplog формат для HAProxy |
| [server-configs/litespeed-httpd.conf](server-configs/litespeed-httpd.conf) | Combined log format для LiteSpeed |

---

## Зворотній проксі / Real-IP

Коли ArxSentinel працює за зворотнім проксі, IP клієнта в лозі може бути IP проксі
замість реального відвідувача. Ці конфігурації виправляють це.

| Схема | Конфігурація проксі | Конфігурація nginx (origin) |
|-------|---------------------|------------------------------|
| nginx за nginx | [reverse-proxy/nginx-rp/nginx-upstream.conf](reverse-proxy/nginx-rp/nginx-upstream.conf) | [reverse-proxy/nginx-rp/nginx-origin.conf](reverse-proxy/nginx-rp/nginx-origin.conf) |
| nginx за Caddy | [reverse-proxy/caddy/Caddyfile](reverse-proxy/caddy/Caddyfile) | [reverse-proxy/caddy/nginx.conf](reverse-proxy/caddy/nginx.conf) |
| nginx за HAProxy | [reverse-proxy/haproxy/haproxy.cfg](reverse-proxy/haproxy/haproxy.cfg) | [reverse-proxy/haproxy/nginx.conf](reverse-proxy/haproxy/nginx.conf) |
| nginx за Traefik | [reverse-proxy/traefik/traefik.yml](reverse-proxy/traefik/traefik.yml) | [reverse-proxy/traefik/nginx.conf](reverse-proxy/traefik/nginx.conf) |

---

## Kubernetes

| Файл | Призначення |
|------|-------------|
| [kubernetes/daemonset.yaml](kubernetes/daemonset.yaml) | DaemonSet: один ArxSentinel на вузол, читання хостових логів |
| [kubernetes/sidecar.yaml](kubernetes/sidecar.yaml) | Sidecar: один ArxSentinel на pod, читання контейнерних логів |
| [kubernetes/configmap.yaml](kubernetes/configmap.yaml) | ConfigMap з типовою конфігурацією ArxSentinel |

---

## Розгортання на FreeBSD

ArxSentinel поставляється з рідною бінарниці для FreeBSD + виділеним інсталятором
(створює системного користувача, встановлює rc.d-сервіс) — контейнеризація самого ArxSentinel
не потрібна. Якщо веб-сервер працює в контейнері `podman` на тому ж хосту FreeBSD,
рантайм FreeBSD `podman` має справжні відмінності від Docker/Linux podman (storage driver,
налаштування firewall, відсутність DNS-розрізнення імен контейнерів, відсутність підтримки
`podman pod`/`podman-compose`), які легко провести полудень без попереднього
розуміння.

| Рецепт | Опис | Файл |
|--------|------|------|
| Повний довідник | Quickstart встановлення/rc.d, розташування файлів FreeBSD, налаштування podman + підводні камені | [freebsd/CookBook.uk.md](freebsd/CookBook.uk.md) |