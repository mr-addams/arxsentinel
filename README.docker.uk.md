# ArxSentinel — посібник з розгортання в Docker

> 🌐 [English](README.docker.md) | [Русский](README.docker.ru.md)

## Швидкий старт

```bash
docker run -d \
  -v /var/log/nginx:/var/log/nginx:ro \
  -v /var/log/arxsentinel:/var/log/arxsentinel \
  -v /etc/arxsentinel:/etc/arxsentinel:ro \
  ghcr.io/mr-addams/arxsentinel:latest
```

Конфігурація усталено читає `/var/log/nginx/access.log` і записує загрози у
`/var/log/arxsentinel/threats.log` у форматі, сумісному з Fail2Ban.

---

## Режим pipe / container (Universal I/O)

При роботі в режимі sidecar або в конвеєрі використовуйте прапорці `--input` і `--output`,
щоб повністю перевизначити секції вводу-виводу конфіг-файлу.

### stdin → stdout (JSON)

```bash
# Пропустити access-лог nginx через ArxSentinel та отримати JSON-події загроз у stdout.
docker logs -f nginx | arxsentinel --input=stdin --output=stdout,json
```

### docker-compose sidecar з іменованим томом

```yaml
services:
  nginx:
    image: nginx:alpine
    volumes:
      - logs:/var/log/nginx

  arxsentinel:
    image: ghcr.io/mr-addams/arxsentinel:latest
    command: ["--input=stdin", "--output=stdout,json"]
    stdin_open: true
    depends_on: [nginx]
    volumes:
      - logs:/var/log/nginx:ro

volumes:
  logs:
```

### Kubernetes — log-forwarding sidecar

```yaml
containers:
  - name: arxsentinel
    image: ghcr.io/mr-addams/arxsentinel:latest
    args: ["--input=stdin", "--output=stdout,json"]
    stdin: true
```

Спрямуйте потік логів основного контейнера в sidecar через спільний том `emptyDir`
або через агент пересилання логів (Fluentd, Vector, Promtail).

---

## Формати виводу

| Прапорець | Формат | Сценарій використання |
|------|--------|-----------------------|
| `--output=stdout` | Текстовий рядок Fail2Ban | Застарілі інструменти, сокет Fail2Ban |
| `--output=stdout,json` | JSON-конверт | Агрегатори логів (Loki, Splunk, Datadog) |
| `--output=stdout,fail2ban` | Текстовий рядок Fail2Ban | Явне значення усталено |

Приклад JSON-конверта:
```json
{
  "timestamp": "2026-05-26T14:33:12Z",
  "level": "THREAT",
  "stream": "",
  "source": "stdin",
  "source_type": "stdin",
  "ip": "1.2.3.4",
  "score": 85,
  "modules": ["probe", "bad_bot"],
  "reason": "probe:env:3,bad_bot:known"
}
```

---

## Множинний вивід (конфіг-файл)

Щоб одночасно писати і в Fail2Ban-файл, і в stdout, використовуйте секцію `outputs:`
у конфізі замість прапорців CLI:

```yaml
inputs:
  - type: file
    path: /var/log/nginx/access.log

outputs:
  - type: file
    path: /var/log/arxsentinel/threats.log
    format: fail2ban
  - type: stdout
    format: json
```

---

## Ротація логів (SIGHUP)

ArxSentinel перевідкриває свої файл-sink'и виводу по `SIGHUP`. Налаштуйте logrotate:

```
/var/log/arxsentinel/threats.log {
    daily
    rotate 30
    compress
    postrotate
        kill -HUP $(cat /run/arxsentinel/arxsentinel.pid) 2>/dev/null || true
    endscript
}
```

---

## Метрики

Метрики Prometheus доступні на `:9117/metrics`, якщо в конфізі вказано `metrics.enabled: true`.

Нові лічильники Universal I/O:

| Метрика | Лейбли | Опис |
|---------|--------|------|
| `arxsentinel_input_lines_total` | stream, source, source_type | Рядки, прочитані з джерел |
| `arxsentinel_output_events_total` | stream, sink, sink_type | Події загроз, записані в sink'и |
| `arxsentinel_output_dropped_total` | stream, sink, reason | Відкинуті події (Phase 2: async sinks) |
