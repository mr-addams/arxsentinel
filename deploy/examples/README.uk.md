# Приклади розгортання

Цей каталог містить приклади конфігурацій для запуску ArxSentinel у різних середовищах.

## Категорії

### Standalone — пряме підключення

ArxSentinel прослуховує HTTP-запити безпосередньо від клієнтів.

| Приклад | Платформа | Файли |
|---------|-----------|-------|
| **Nginx** | Nginx | `nginx-json-logformat.conf` — фрагменти формату журналів для прямого nginx + JSON |
| **Apache** | Apache 2.4+ | `apache/httpd.conf`, `apache/sentinel-config.yaml` |
| **Caddy** | Caddy 2.x | `caddy/Caddyfile`, `caddy/sentinel-config.yaml` |
| **HAProxy** | HAProxy 2.x+ | `haproxy/haproxy.cfg`, `haproxy/sentinel-config.yaml` |
| **Traefik** | Traefik 2.x+ | `traefik/traefik.yml`, `traefik/sentinel-config.yaml` |
| **LiteSpeed** | LiteSpeed 5.4+ | `litespeed/httpd_config.conf`, `litespeed/sentinel-config.yaml` |

**Коли використовувати:** пряме підключення клієнтів, одношарова архітектура або роль шлюзу.

### Reverse Proxy — за зворотним проксі

ArxSentinel розгорнутий за зворотним проксі (nginx, Caddy, HAProxy або Traefik),
який пересилає записи журналів на аналіз.

Повний посібник — [reverse-proxy/README.uk.md](reverse-proxy/README.uk.md):
перевірка ланцюга IP, захист Cloudflare та налаштування шлюзу.

| Приклад | Проксі + ArxSentinel | Файли |
|---------|----------------------|-------|
| **Nginx** | nginx → ArxSentinel | `reverse-proxy/nginx-rp/` — nginx.conf + sentinel-config |
| **Caddy** | Caddy → ArxSentinel | `reverse-proxy/caddy/` — Caddyfile + sentinel-config |
| **HAProxy** | HAProxy → ArxSentinel | `reverse-proxy/haproxy/` — haproxy.cfg + sentinel-config |
| **Traefik** | Traefik → ArxSentinel | `reverse-proxy/traefik/` — traefik.yml + sentinel-config |

**Коли використовувати:** багатошарова архітектура, балансування навантаження, Kubernetes Ingress
або розміщення за існуючим зворотним проксі.

### Інтеграція з CMS

Попередньо налаштовані приклади для популярних систем управління контентом.

| Платформа | Приклади | Розташування |
|-----------|----------|--------------|
| **WordPress** | Generic + Multisite | `cms/wordpress.yaml` |
| **Drupal** | Drupal 9, 10 | `cms/drupal.yaml` |
| **Joomla** | Joomla 3, 4 | `cms/joomla.yaml` |
| **Laravel** | Laravel 9+ | `cms/laravel.yaml` |
| **Generic PHP** | Будь-який PHP-фреймворк | `cms/generic-php.yaml` |

## Швидкий старт

1. Виберіть ваш сценарій вище (standalone або reverse proxy).
2. Скопіюйте відповідний `sentinel-config.yaml` у вашу середу розгортання.
3. Налаштуйте порти, шляхи журналів та правила для ваших потреб.
4. Повний посібник інтеграції — `../../README.uk.md`, контейнеризоване розгортання — `deploy/docker/`.

## Конфігурація формату журналів

Для Nginx з прямим підключенням використовуйте `nginx-json-logformat.conf`
для встановлення правильного формату журналів для JSON-парсингу.
Приклади зі зворотним проксі вже включають необхідні директиви формату журналів.

## Додаткова інформація

- **Правила Whitelist:** [./README.whitelist.uk.md](./README.whitelist.uk.md)
- **Перевірка ланцюга та захист від bogon:** [reverse-proxy/README.uk.md](reverse-proxy/README.uk.md)
- **Метрики та моніторинг:** [../../deploy/grafana/README.md](../../deploy/grafana/README.md)
- **Користувацькі формати журналів:** [./README.log-formats.uk.md](./README.log-formats.uk.md)
