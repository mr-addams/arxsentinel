# ArxSentinel — руководство по развёртыванию в Docker

> 🌐 [English](README.docker.md) | [Українська](README.docker.uk.md)

## Быстрый старт

```bash
docker run -d \
  -v /var/log/nginx:/var/log/nginx:ro \
  -v /var/log/arxsentinel:/var/log/arxsentinel \
  -v /etc/arxsentinel:/etc/arxsentinel:ro \
  ghcr.io/mr-addams/arxsentinel:latest
```

Конфигурация по умолчанию читает `/var/log/nginx/access.log` и записывает угрозы в
`/var/log/arxsentinel/threats.log` в формате, совместимом с Fail2Ban.

---

## Режим pipe / container (Universal I/O)

При работе в режиме sidecar или в пайплайне используйте флаги `--input` и `--output`,
чтобы полностью переопределить секции ввода-вывода конфиг-файла.

### stdin → stdout (JSON)

```bash
# Пропустить access-лог nginx через ArxSentinel и получить JSON-события угроз в stdout.
docker logs -f nginx | arxsentinel --input=stdin --output=stdout,json
```

### docker-compose sidecar с именованным томом

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

Направьте поток логов основного контейнера в sidecar через общий том `emptyDir`
или через агент пересылки логов (Fluentd, Vector, Promtail).

---

## Форматы вывода

| Флаг | Формат | Сценарий использования |
|------|--------|-----------------------|
| `--output=stdout` | Текстовая строка Fail2Ban | Устаревшие инструменты, сокет Fail2Ban |
| `--output=stdout,json` | JSON-конверт | Агрегаторы логов (Loki, Splunk, Datadog) |
| `--output=stdout,fail2ban` | Текстовая строка Fail2Ban | Явное значение по умолчанию |

Пример JSON-конверта:
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

## Множественный вывод (конфиг-файл)

Чтобы одновременно писать и в Fail2Ban-файл, и в stdout, используйте секцию `outputs:`
в конфиге вместо флагов CLI:

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

## Ротация логов (SIGHUP)

ArxSentinel переоткрывает свои файл-sink'и вывода по `SIGHUP`. Настройте logrotate:

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

Метрики Prometheus доступны на `:9117/metrics`, если в конфиге указано `metrics.enabled: true`.

Новые счётчики Universal I/O:

| Метрика | Лейблы | Описание |
|---------|--------|----------|
| `arxsentinel_input_lines_total` | stream, source, source_type | Строки, прочитанные из источников |
| `arxsentinel_output_events_total` | stream, sink, sink_type | События угроз, записанные в sink'и |
| `arxsentinel_output_dropped_total` | stream, sink, reason | Отброшенные события (Phase 2: async sinks) |
