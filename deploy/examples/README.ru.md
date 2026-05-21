# Примеры развёртывания

Этот каталог содержит примеры конфигурации для запуска ArxSentinel в различных окружениях.

## Категории

### Standalone — прямое подключение

ArxSentinel слушает HTTP-запросы непосредственно от клиентов.

| Пример | Платформа | Файлы |
|--------|-----------|-------|
| **Nginx** | Nginx | `nginx-json-logformat.conf` — фрагменты формата логов для прямого nginx + JSON |
| **Apache** | Apache 2.4+ | `apache/httpd.conf`, `apache/sentinel-config.yaml` |
| **Caddy** | Caddy 2.x | `caddy/Caddyfile`, `caddy/sentinel-config.yaml` |
| **HAProxy** | HAProxy 2.x+ | `haproxy/haproxy.cfg`, `haproxy/sentinel-config.yaml` |
| **Traefik** | Traefik 2.x+ | `traefik/traefik.yml`, `traefik/sentinel-config.yaml` |
| **LiteSpeed** | LiteSpeed 5.4+ | `litespeed/httpd_config.conf`, `litespeed/sentinel-config.yaml` |

**Когда использовать:** прямое подключение клиентов, однослойная архитектура или роль шлюза.

### Reverse Proxy — за обратным прокси

ArxSentinel развёрнут за обратным прокси (nginx, Caddy, HAProxy или Traefik),
который пересылает записи логов на анализ.

Полное руководство — [reverse-proxy/README.ru.md](reverse-proxy/README.ru.md):
проверка цепи IP, защита Cloudflare и настройка шлюза.

| Пример | Прокси + ArxSentinel | Файлы |
|--------|----------------------|-------|
| **Nginx** | nginx → ArxSentinel | `reverse-proxy/nginx-rp/` — nginx.conf + sentinel-config |
| **Caddy** | Caddy → ArxSentinel | `reverse-proxy/caddy/` — Caddyfile + sentinel-config |
| **HAProxy** | HAProxy → ArxSentinel | `reverse-proxy/haproxy/` — haproxy.cfg + sentinel-config |
| **Traefik** | Traefik → ArxSentinel | `reverse-proxy/traefik/` — traefik.yml + sentinel-config |

**Когда использовать:** многослойная архитектура, балансировка нагрузки, Kubernetes Ingress
или размещение за существующим обратным прокси.

### Интеграция с CMS

Предконфигурированные примеры для популярных систем управления контентом.

| Платформа | Примеры | Расположение |
|-----------|---------|--------------|
| **WordPress** | Generic + Multisite | `cms/wordpress.yaml` |
| **Drupal** | Drupal 9, 10 | `cms/drupal.yaml` |
| **Joomla** | Joomla 3, 4 | `cms/joomla.yaml` |
| **Laravel** | Laravel 9+ | `cms/laravel.yaml` |
| **Generic PHP** | Любой PHP-фреймворк | `cms/generic-php.yaml` |

## Быстрый старт

1. Выберите ваш сценарий выше (standalone или reverse proxy).
2. Скопируйте соответствующий `sentinel-config.yaml` в вашу среду развёртывания.
3. Настройте порты, пути логов и правила под свои нужды.
4. Полное руководство интеграции — `../../README.ru.md`, контейнеризованное развёртывание — `deploy/docker/`.

## Конфигурация формата логов

Для Nginx с прямым подключением используйте `nginx-json-logformat.conf`
для установки правильного формата логов для JSON-парсинга.
Примеры с reverse proxy уже включают необходимые директивы формата логов.

## Дополнительная информация

- **Правила Whitelist:** [../../README.whitelist.ru.md](../../README.whitelist.ru.md)
- **Проверка цепи и защита от bogon:** [reverse-proxy/README.ru.md](reverse-proxy/README.ru.md)
- **Метрики и мониторинг:** [../../deploy/grafana/README.md](../../deploy/grafana/README.md)
- **Пользовательские форматы логов:** [../../README.log-formats.ru.md](../../README.log-formats.ru.md)
