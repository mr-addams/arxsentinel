## JSON-формат логов

По умолчанию ArxSentinel парсит nginx combined log format (профиль не требуется) или формат, определённый активным профилем (apache, caddy, traefik, haproxy-http или litespeed).  
Поддерживается также JSON-формат — переключается через `config.yaml` без перекомпиляции.

Примеры ниже используют nginx. Для других серверов адаптируйте директиву `log_format` к вашему серверу.

### Шаг 1 — Настройка HTTP-сервера (пример nginx)

Добавьте нужный `log_format` в блок `http {}` файла `nginx.conf`.
Готовые конфиги также в [`deploy/examples/nginx-json-logformat.conf`](deploy/examples/nginx-json-logformat.conf).

**Прямой nginx (без прокси)** — `$remote_addr` содержит реальный IP клиента:

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

**За обратным прокси** — настройте `ngx_http_realip_module` (см.
[Деплой за обратным прокси](#деплой-за-обратным-прокси)).
После обработки realip `$remote_addr` уже содержит реальный IP клиента,
поэтому тот же формат `sentinel_json_direct` работает без изменений — отдельный proxy-вариант не нужен.

### Шаг 2 — Обновить конфиг sentinel

```yaml
parser:
  log_format: "json"   # "combined" (по умолчанию) | "json"
```

Изменение вступает в силу после **SIGHUP** — рестарт не нужен:

```bash
kill -HUP $(cat /var/run/arxsentinel.pid)
```

### Кастомные имена полей

Если в вашем формате логов используются другие ключи — переопределите маппинг:

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

Неизвестные поля в JSON-строке игнорируются — потребляются только поля из маппинга.

## Произвольный формат логов (regex)

Используйте любой текстовый формат логов, указав Go-регулярное выражение с именованными группами.

```yaml
parser:
  log_format: "regex"
  regex_pattern: '(?P<remote_addr>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] "(?P<request>[^"]*)" (?P<status>\d+) (?P<bytes_sent>\d+) "(?P<http_referer>[^"]*)" "(?P<http_user_agent>[^"]*)"'
```

### Именованные группы

| Группа | Обязательная | Описание |
|--------|-------------|----------|
| `remote_addr` | ✅ | IP-адрес клиента или прокси |
| `time` | ✅ | Время запроса (формат `02/Jan/2006:15:04:05 -0700`) |
| `request` | ✅ | Строка запроса: `METHOD /path HTTP/x.x` |
| `status` | ✅ | HTTP-код ответа |
| `bytes_sent` | ✅ | Размер ответа в байтах |
| `http_referer` | опциональная | Значение заголовка Referer |
| `http_user_agent` | опциональная | Значение заголовка User-Agent |
| `real_ip` | опциональная | Реальный IP клиента из заголовка доверенного прокси |

Отсутствующие опциональные группы дают пустые поля — sentinel продолжает работу.

### Пример: HAProxy HTTP log

```yaml
parser:
  log_format: "regex"
  regex_pattern: '(?P<remote_addr>\S+):\d+ \S+ \S+/\S+ \d+/\d+/\d+/\d+/\d+ (?P<status>\d+) (?P<bytes_sent>\d+) .* "(?P<request>[^"]*)"'
```

### Типичные ошибки

- **Отсутствует обязательная группа** — sentinel завершается при старте с понятным сообщением об ошибке.
- **Неверный формат времени** — поддерживается только `02/Jan/2006:15:04:05 -0700` (nginx `$time_local`). ISO 8601 не парсится; детекторы без временны́х зависимостей работают в любом случае.
