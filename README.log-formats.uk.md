## JSON-формат логів

За замовчуванням ArxSentinel парсить nginx combined log format (профіль не потрібен) або формат, визначений активним профілем (apache, caddy, traefik, haproxy-http або litespeed).  
Підтримується також JSON-формат — перемикається через `config.yaml` без перекомпіляції.

Приклади нижче використовують nginx. Для інших серверів адаптуйте директиву `log_format` до вашого сервера.

### Крок 1 — Налаштування HTTP-сервера (приклад nginx)

Додайте потрібний `log_format` у блок `http {}` файлу `nginx.conf`.
Готові конфіги також у [`deploy/examples/nginx-json-logformat.conf`](deploy/examples/nginx-json-logformat.conf).

**Прямий nginx (без проксі)** — `$remote_addr` містить реальний IP клієнта:

```nginx
log_format sentinel_json_direct escape=json
    '{'
        '"remote_addr":"$remote_addr",'
        '"time_iso8601":"$time_iso8601",'
        '"request":"$request",'
        '"status":"$status",'
        '"bytes_sent":"$bytes_sent",'
        '"http_referer":"$http_referer",'
        '"http_user_agent":"$http_user_agent"'
    '}';

access_log /var/log/nginx/access.log sentinel_json_direct;
```

**За зворотним проксі** — налаштуйте `ngx_http_realip_module` (див.
[Деплой за зворотним проксі](#деплой-за-зворотним-проксі)).
Після обробки realip `$remote_addr` вже містить реальний IP клієнта,
тому той самий формат `sentinel_json_direct` працює без змін — окремий proxy-варіант не потрібен.

### Крок 2 — Оновити конфіг sentinel

```yaml
parser:
  log_format: "json"   # "combined" (за замовчуванням) | "json"
```

Зміна набирає чинності після **SIGHUP** — перезапуск не потрібен:

```bash
kill -HUP $(cat /var/run/arxsentinel.pid)
```

### Кастомні імена полів

Якщо у вашому форматі логів використовуються інші ключі — перевизначте маппінг:

```yaml
parser:
  log_format: "json"
  json_fields:
    remote_addr: "client"
    time:        "ts"
    request:     "req"
    status:      "code"
    bytes_sent:  "size"
    referer:     "ref"
    user_agent:  "ua"
    real_ip:     "ip"
```

Невідомі поля в JSON-рядку ігноруються — споживаються лише поля з маппінгу.

## Довільний формат логів (regex)

Використовуйте будь-який текстовий формат логів, вказавши Go-регулярний вираз з іменованими групами.

```yaml
parser:
  log_format: "regex"
  regex_pattern: '(?P<remote_addr>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<request>[^"]*)" (?P<status>\d+) (?P<bytes_sent>\d+) "(?P<http_referer>[^"]*)" "(?P<http_user_agent>[^"]*)"'
```

### Іменовані групи

| Група | Обов'язкова | Опис |
|-------|------------|------|
| `remote_addr` | ✅ | IP-адреса клієнта або проксі |
| `time` | ✅ | Час запиту (формат `02/Jan/2006:15:04:05 -0700`) |
| `request` | ✅ | Рядок запиту: `METHOD /path HTTP/x.x` |
| `status` | ✅ | HTTP-код відповіді |
| `bytes_sent` | ✅ | Розмір відповіді в байтах |
| `http_referer` | опційна | Значення заголовка Referer |
| `http_user_agent` | опційна | Значення заголовка User-Agent |
| `real_ip` | опційна | Реальний IP клієнта з заголовка довіреного проксі |

Відсутні опційні групи дають порожні поля — sentinel продовжує роботу.

### Приклад: HAProxy HTTP log

```yaml
parser:
  log_format: "regex"
  regex_pattern: '(?P<remote_addr>\S+):\d+ \S+ \S+/\S+ \d+/\d+/\d+/\d+/\d+ (?P<status>\d+) (?P<bytes_sent>\d+) .* "(?P<request>[^"]*)"'
```

### Типові помилки

- **Відсутня обов'язкова група** — sentinel завершується при старті з зрозумілим повідомленням про помилку.
- **Невірний формат часу** — підтримується лише `02/Jan/2006:15:04:05 -0700` (nginx `$time_local`). ISO 8601 не парситься; детектори без часових залежностей працюють у будь-якому разі.
