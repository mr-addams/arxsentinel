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
| `whitelist.custom` | Довірені IP/CIDR/UA | ✅ |
| `chain_guard` | Цілісність проксі-ланцюжка | опційно |
| `streams.outputs` | Приймачі подій | ✅ |
| `executors` | Автоматизована відповідь | лише рецепти з executor |

## Зміст

- [Fail2Ban (file-based logging)](#fail2ban)
- [Cloudflare Executor (автоматичне блокування IP)](#cloudflare)
- [MikroTik Executor (address-list на RouterOS)](#mikrotik)
- [Nginx Executor (файл блокування + перезавантаження)](#nginx-executor)
- [Інфраструктура: Конфігурації серверів](#server-configs)
- [Інфраструктура: Зворотній проксі / Real-IP](#reverse-proxy)
- [Інфраструктура: Kubernetes](#kubernetes)

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

## Cloudflare

ArxSentinel надсилає події THREAT до Cloudflare API для блокування IP через firewall rules.
Потрібен токен Cloudflare API з дозволом Zone Firewall edit.

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